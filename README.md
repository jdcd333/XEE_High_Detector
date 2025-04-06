# Advanced XXE Scanner 🛡️

A multi-threaded XML External Entity (XXE) vulnerability scanner with comprehensive reporting.

## Features
- Multiple XXE payload testing (file read, OOB, etc.)
- Customizable endpoints and configurations
- Multi-threaded scanning
- JSON output with detailed results
- Color-coded console output
- OOB (Out-of-Band) testing support
- Configurable via JSON file

## Installation

```bash
git clone https://github.com/yourusername/xxe-scanner.git
cd xxe-scanner
pip install -r requirements.txt
```

Usage

```bash
python xxe_scanner.py -i targets.txt -o results.json
```
Options:
-i/--input: Input file with target URLs (required)

-o/--output: Output file (default: xxe_scan_results.json)

-t/--threads: Concurrent threads (default: 20)

-to/--timeout: Request timeout (default: 15s)

-c/--config: Custom configuration JSON file

-oa/--oob-server: OOB test server URL

-v/--verbose: Verbose output

Sample Configuration
Create config.json:

```json

{
    "endpoints": ["/api", "/upload"],
    "user_agent": "Custom User Agent"
}
```
