# IP Scanner

A Python GUI-based IP and port scanner built with Tkinter and the Python standard library.

## Features

- Scan a CIDR range for reachable IP addresses
- Probe common TCP ports and collect banners and HTTP server information
- Display scan results in a Tkinter desktop interface
- Export or persist scan results in JSON format

## Run locally

```bash
python scanner_W.py
```

## Project structure

- `scanner_W.py` - main GUI scanner implementation
- `scan_results.json` - sample scan output
- `real.txt`, `test.txt`, `test2.txt` - sample input data

## Notes

This project uses Python standard-library modules only and depends on Tkinter for the desktop GUI.
