import ipaddress
import asyncio
import socket
import http.client
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
import time

STOP_SCAN = False

# ================= UTIL =================

def get_ips(cidr):
    return [str(ip) for ip in ipaddress.ip_network(cidr, strict=False)]

def resolve_ip(host):
    try:
        return socket.gethostbyname(host)
    except:
        return None

def ip_to_cidr(ip):
    return ".".join(ip.split(".")[:3]) + ".0/24"

# ================= SERVICE DETECTION =================

def detect_service(server, banner):
    text = (server + " " + banner).lower()
    if "apache" in text:
        return "Apache"
    elif "nginx" in text:
        return "Nginx"
    elif "iis" in text:
        return "IIS"
    elif "lighttpd" in text:
        return "Lighttpd"
    else:
        return "Unknown"

# ================= HTTP =================

def http_probe(ip, port, timeout):
    try:
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request("GET", "/")
        res = conn.getresponse()
        headers = dict(res.getheaders())
        banner = f"{res.status} {res.reason}"
        server = headers.get("Server", "")
        conn.close()
        return banner, server
    except:
        return "", ""

# ================= SCAN =================

async def scan_port(ip, port, timeout):
    loop = asyncio.get_event_loop()

    def run():
        banner, server = "", ""
        start = time.perf_counter()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(min(timeout, 0.3))
        if sock.connect_ex((ip, port)) != 0:
            sock.close()
            return (port, False, "", "", None)
        sock.close()

        latency = (time.perf_counter() - start) * 1000  # ms

        if port in (80, 443):
            banner, server = http_probe(ip, port, timeout)

        return (port, bool(banner), banner, server, latency)

    return await loop.run_in_executor(None, run)

async def scan_ip(ip, ports, timeout, sem):
    global STOP_SCAN
    if STOP_SCAN:
        return None
    async with sem:
        tasks = [scan_port(ip, p, timeout) for p in ports]
        ports_data = await asyncio.gather(*tasks)
        return {"ip": ip, "ports": ports_data}

async def run_scan(cidr, ports, timeout, callback, concurrency):
    global STOP_SCAN
    STOP_SCAN = False
    ips = get_ips(cidr)
    sem = asyncio.Semaphore(concurrency)
    tasks = [scan_ip(ip, ports, timeout, sem) for ip in ips]
    total = len(tasks)
    done = 0
    for f in asyncio.as_completed(tasks):
        if STOP_SCAN:
            break
        res = await f
        done += 1
        if res:
            callback(res, done, total)

# ================= GUI =================

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("⚡ Pro Scanner v3.2")
        self.root.geometry("1300x700")
        self.dark_mode = True
        self.scan_results = []

        self.style = ttk.Style()
        self.style.theme_use('clam') 
        
        self.build_ui()
        self.apply_theme()

    def build_ui(self):
        main_container = tk.Frame(self.root)
        main_container.pack(fill="both", expand=True)
        
        top = ttk.Frame(main_container, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="CIDR").grid(row=0, column=0, padx=5, pady=2)
        self.cidr = ttk.Entry(top, width=18)
        self.cidr.insert(0, "192.168.1.0/24")
        self.cidr.grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(top, text="Host").grid(row=0, column=2, padx=5, pady=2)
        self.host = ttk.Entry(top, width=15)
        self.host.grid(row=0, column=3, padx=5, pady=2)
        self.host.bind("<Return>", self.auto_cidr)

        ttk.Label(top, text="Ports").grid(row=0, column=4, padx=5, pady=2)
        self.ports = ttk.Entry(top, width=20)
        self.ports.insert(0, "80,443")
        self.ports.grid(row=0, column=5, padx=5, pady=2)

        ttk.Label(top, text="Timeout").grid(row=0, column=6, padx=5, pady=2)
        self.timeout = ttk.Entry(top, width=5)
        self.timeout.insert(0, "1")
        self.timeout.grid(row=0, column=7, padx=5, pady=2)

        ttk.Label(top, text="Speed").grid(row=1, column=0, padx=5, pady=2)
        self.speed = tk.Scale(top, from_=10, to=300, orient="horizontal", length=150)
        self.speed.set(120)
        self.speed.grid(row=1, column=1, padx=5, pady=2)

        self.search = ttk.Entry(top, width=30)
        self.search.grid(row=1, column=2, columnspan=2, padx=5, pady=2)
        self.search.bind("<KeyRelease>", self.filter_results)

        self.only_open = tk.BooleanVar()
        ttk.Checkbutton(top, text="Only Open", variable=self.only_open).grid(row=1, column=4, padx=5, pady=2)

        # Buttons
        ttk.Button(top, text="▶ Start", command=self.start).grid(row=2, column=0, padx=5, pady=5)
        ttk.Button(top, text="■ Stop", command=self.stop).grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(top, text="🧹 Clear", command=self.clear).grid(row=2, column=2, padx=5, pady=5)
        ttk.Button(top, text="🌙 Theme", command=self.toggle_theme).grid(row=2, column=3, padx=5, pady=5)
        ttk.Button(top, text="💾 Export JSON", command=self.export_json).grid(row=2, column=4, padx=5, pady=5)
        ttk.Button(top, text="⚡ Fastest IP", command=self.show_fastest_ip).grid(row=2, column=5, padx=5, pady=5)

        self.progress = ttk.Progressbar(main_container, length=600, mode='determinate')
        self.progress.pack(pady=10, padx=10)

        table_frame = tk.Frame(main_container)
        table_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.tree = ttk.Treeview(
            table_frame,
            columns=("IP","Port","Status","Service","Banner","Server","Latency (ms)"),
            show="headings"
        )

        for c in ("IP","Port","Status","Service","Banner","Server","Latency (ms)"):
            self.tree.heading(c, text=c)
            self.tree.column(c, anchor="center", width=120)

        self.tree.pack(side="left", fill="both", expand=True)

        tree_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        tree_scroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=tree_scroll.set)

        self.tree.tag_configure("open", foreground="#4caf50")
        self.tree.tag_configure("closed", foreground="#f44336")

        self.tree.bind("<ButtonRelease-1>", self.copy_ip)

    def apply_theme(self):
        bg = "#2d2d2d" if self.dark_mode else "#f0f0f0"
        self.root.configure(bg=bg)

    def toggle_theme(self):
        self.dark_mode = not self.dark_mode
        self.apply_theme()

    def start(self):
        threading.Thread(target=self.run_async, daemon=True).start()

    def run_async(self):
        cidr = self.cidr.get()
        ports = list(map(int, self.ports.get().split(",")))
        timeout = float(self.timeout.get())
        concurrency = int(self.speed.get())
        asyncio.run(run_scan(cidr, ports, timeout, self.update_ui, concurrency))

    def stop(self):
        global STOP_SCAN
        STOP_SCAN = True

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.scan_results.clear()
        self.progress["value"] = 0

    def filter_results(self, event=None):
        keyword = self.search.get().lower()
        for item in self.tree.get_children():
            values = self.tree.item(item)["values"]
            text = " ".join(map(str, values)).lower()
            if keyword in text:
                self.tree.reattach(item, "", "end")
            else:
                self.tree.detach(item)

    def copy_ip(self, event):
        item = self.tree.selection()
        if item:
            ip = self.tree.item(item[0])["values"][0]
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)

    def auto_cidr(self, event=None):
        ip = resolve_ip(self.host.get())
        if ip:
            self.cidr.delete(0, tk.END)
            self.cidr.insert(0, ip_to_cidr(ip))

    def update_ui(self, res, done, total):
        self.progress["maximum"] = total
        self.progress["value"] = done

        for port, open_, banner, server, latency in res["ports"]:
            if self.only_open.get() and not open_:
                continue

            service = detect_service(server, banner)
            status = "OPEN" if open_ else "CLOSED"
            tag = "open" if open_ else "closed"

            self.tree.insert("", "end", 
                values=(res["ip"], port, status, service, banner, server, 
                        f"{latency:.2f}" if latency else ""),
                tags=(tag,))

            self.scan_results.append({
                "ip": res["ip"],
                "port": port,
                "status": status,
                "service": service,
                "banner": banner,
                "server": server,
                "latency": latency
            })

        self.root.update()

    def export_json(self):
        if not self.scan_results:
            messagebox.showwarning("Export", "No scan data available to export!")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
            title="Save Scan Results"
        )
        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
                messagebox.showinfo("Success", f"✅ Successfully exported {len(self.scan_results)} records to:\n{file_path}")
            except Exception as e:
                messagebox.showerror("Export Failed", f"❌ Error: {str(e)}")

    def show_fastest_ip(self):
        open_ports = [r for r in self.scan_results if r["status"] == "OPEN" and r.get("latency")]
        if not open_ports:
            messagebox.showwarning("Fastest IP", "No open IPs with latency found!")
            return
        fastest = min(open_ports, key=lambda x: x["latency"])
        messagebox.showinfo("Fastest IP", f"⚡ Fastest IP: {fastest['ip']}\nLatency: {fastest['latency']:.2f} ms")

# ================= RUN =================

if __name__ == "__main__":
    root = tk.Tk()
    App(root)
    root.mainloop()
