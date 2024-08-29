import argparse
import asyncio
import json
import logging
import os
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from aiohttp import ClientSession
from colorama import init, Fore, Style

# Initialize Colorama
init(autoreset=True)

# Constants and Configuration
CONFIG_FILE = 'scanem_config.json'
DEFAULT_CONFIG = {
    'gau_path': 'gau',
    'urldedupe_path': 'urldedupe',
    'gf_path': 'gf',
    'httpx_path': 'httpx',
    'max_concurrency': 5,
    'rate_limit': 0  # 0 means no limit
}

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Config:
    def __init__(self):
        self.data = self.load_config()

    @staticmethod
    def load_config() -> Dict[str, Any]:
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.error(f"Error parsing {CONFIG_FILE}. Using default configuration.")
        return DEFAULT_CONFIG

    def __getitem__(self, key: str) -> Any:
        return self.data.get(key)

config = Config()

def print_color(color: str, prefix: str, message: str):
    print(f"{color}{prefix}:{Style.RESET_ALL} {message}")

def print_info(message: str):
    print_color(Fore.CYAN, "INFO", message)

def print_success(message: str):
    print_color(Fore.GREEN, "SUCCESS", message)

def print_error(message: str):
    print_color(Fore.RED, "ERROR", message)

def print_warning(message: str):
    print_color(Fore.YELLOW, "WARNING", message)

def sanitize_filename(url: str) -> str:
    """Sanitize URL to create a valid filename."""
    return ''.join(c if c.isalnum() or c in '-_' else '_' for c in url)

async def run_command(command: List[str], input_data: Optional[str] = None) -> Optional[str]:
    """Run a system command asynchronously and capture the output."""
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE if input_data else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate(input_data.encode() if input_data else None)
        if process.returncode != 0:
            logger.error(f"Command failed: {' '.join(command)}")
            logger.error(f"Error: {stderr.decode().strip()}")
            return None
        return stdout.decode().strip()
    except Exception as e:
        logger.error(f"Command failed: {e}")
        return None

async def scan_domain(domain: str, scan_type: str, output_dir: str, quiet: bool) -> List[str]:
    """Scan a domain for specific vulnerabilities using given tools."""
    output_file = os.path.join(output_dir, f"{sanitize_filename(domain)}_{scan_type}_scan.txt")

    if not quiet:
        print_info(f"Scanning {domain} for {scan_type} vulnerabilities...")

    gau_output = await run_command([config['gau_path'], domain])
    if gau_output is None or not gau_output:
        logger.warning(f"No URLs found for {domain}")
        return []

    urldedupe_output = await run_command([config['urldedupe_path'], '-qs'], gau_output)
    if urldedupe_output is None or not urldedupe_output:
        logger.warning(f"No unique URLs found for {domain}")
        return []

    gf_output = await run_command([config['gf_path'], scan_type], urldedupe_output)
    if gf_output is None:
        logger.warning(f"No {scan_type} vulnerabilities found for {domain}")
        return []

    results = gf_output.splitlines()

    with open(output_file, 'w') as f:
        f.write(gf_output)

    return results

async def find_subdomains(domain: str, output_dir: str) -> List[str]:
    """Find subdomains using `httpx` or fallback to other tools if needed."""
    subdomains_file = os.path.join(output_dir, f"{sanitize_filename(domain)}_subdomains.txt")
    print_info(f"Finding subdomains for {domain}...")

    # Use `httpx` for subdomain enumeration
    httpx_output = await run_command([config['httpx_path'], "-silent", "-u", domain, "-extract-fqdn", "-o", subdomains_file])

    if os.path.exists(subdomains_file):
        with open(subdomains_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        if not domains:
            print_warning("No subdomains found. Scanning main domain only.")
            domains = [domain]
    else:
        print_warning("No subdomains file created. Scanning main domain only.")
        domains = [domain]

    return domains

async def main():
    parser = argparse.ArgumentParser(description="Enhanced web vulnerability scanner")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-t", "--types", nargs="+", default=["sqli"], help="Scan types (default: sqli)")
    parser.add_argument("-d", "--output-dir", default=".", help="Output directory for results")
    parser.add_argument("-c", "--concurrency", type=int, default=config['max_concurrency'], help="Maximum number of concurrent scans")
    parser.add_argument("-q", "--quiet", action="store_true", help="Quiet mode: suppress non-critical output")
    parser.add_argument("--no-subdomains", action="store_true", help="Don't scan subdomains")
    args = parser.parse_args()

    # Input validation
    if not urlparse(args.domain).scheme:
        args.domain = f"http://{args.domain}"

    os.makedirs(args.output_dir, exist_ok=True)

    domains = [args.domain]
    if not args.no_subdomains:
        domains = await find_subdomains(args.domain, args.output_dir)

    results = {domain: {scan_type: [] for scan_type in args.types} for domain in domains}

    async def process_domain(domain: str, scan_type: str):
        vulnerabilities = await scan_domain(domain, scan_type, args.output_dir, args.quiet)
        results[domain][scan_type] = vulnerabilities

    tasks = []
    for domain in domains:
        for scan_type in args.types:
            tasks.append(process_domain(domain, scan_type))

    # Use asyncio.Semaphore to limit concurrency
    semaphore = asyncio.Semaphore(args.concurrency)
    async def bounded_scan(coro):
        async with semaphore:
            return await coro
    await asyncio.gather(*(bounded_scan(task) for task in tasks))

    print("\nScan Summary:")
    for domain, domain_results in results.items():
        print(f"Domain: {domain}")
        for scan_type, vulnerabilities in domain_results.items():
            print(f"  {scan_type}: {len(vulnerabilities)} potential vulnerabilities found")

if __name__ == "__main__":
    asyncio.run(main())
