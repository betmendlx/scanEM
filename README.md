# ScanEM

**ScanEM** is an advanced web vulnerability scanning tool that leverages powerful tools like `httpx`, `gau`, `gf`, and `urldedupe` to perform comprehensive security assessments of web applications. The tool is designed to find subdomains, extract URLs, and scan for various vulnerabilities such as SQL injection (SQLi), Cross-Site Scripting (XSS), and more.

## Features

- **Subdomain Enumeration:** Uses `httpx` to find subdomains of a given domain.
- **URL Extraction and Deduplication:** Utilizes `gau` and `urldedupe` to gather and clean URLs from various sources.
- **Vulnerability Scanning:** Supports scanning for multiple types of vulnerabilities, including SQL Injection (SQLi) and more.
- **Asynchronous Scanning:** Scans multiple domains concurrently for faster results.
- **Customizable:** Easily configurable through a JSON configuration file.
- **Detailed Output:** Generates scan results in readable and customizable formats.

## Requirements

- Python 3.8 or higher
- `httpx` (https://github.com/projectdiscovery/httpx)
- `gau` (https://github.com/lc/gau)
- `gf` (https://github.com/tomnomnom/gf)
- `urldedupe` (https://github.com/robre/gf)
- `aiohttp` Python library
- `colorama` Python library

## Installation

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/betmendlx/scanem.git
   cd scanem
   ```

2. **Install Required Python Libraries:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Install External Tools:**
   Ensure `httpx`, `gau`, `gf`, and `urldedupe` are installed and accessible in your system's PATH. You can install them using the following commands:

   - **httpx:**
     ```bash
     go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
     ```
   
   - **gau:**
     ```bash
     go install github.com/lc/gau/v2/cmd/gau@latest
     ```

   - **gf:**
     ```bash
     go install github.com/tomnomnom/gf@latest
     ```

   - **urldedupe:**
     ```bash
     go install github.com/robre/gf/urldedupe@latest
     ```

4. **Configure `gf` Patterns:**
   Install and configure `gf` patterns to use with the tool:
   ```bash
   git clone https://github.com/1ndianl33t/Gf-Patterns
   mv Gf-Patterns/*.json ~/.gf
   ```

## Usage

```bash
python3 ScanEM.py <domain> [options]
```

### Examples

1. **Basic SQL Injection Scan:**
   ```bash
   python3 ScanEM.py example.com -t sqli
   ```

2. **Quiet Mode with Custom Output Directory:**
   ```bash
   python3 ScanEM.py example.com -t sqli -q -d /output/directory
   ```

3. **Scan Without Subdomain Enumeration:**
   ```bash
   python3 ScanEM.py example.com -t sqli --no-subdomains
   ```

### Command-Line Arguments

- `domain`: Target domain to scan.
- `-t, --types`: Scan types (default: `sqli`). Supports multiple types like `xss`, `lfi`, etc.
- `-d, --output-dir`: Output directory for results (default: current directory).
- `-c, --concurrency`: Maximum number of concurrent scans (default: 5).
- `-q, --quiet`: Quiet mode; suppress non-critical output.
- `--no-subdomains`: Don't scan subdomains.

## Configuration

You can customize the tool settings in the `scanem_config.json` file. Here is an example configuration:

```json
{
    "gau_path": "gau",
    "urldedupe_path": "urldedupe",
    "gf_path": "gf",
    "httpx_path": "httpx",
    "max_concurrency": 5,
    "rate_limit": 0
}
```

- **`max_concurrency`**: Maximum number of concurrent tasks.
- **`rate_limit`**: Rate limit for scanning (0 means no limit).

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature-branch`).
5. Open a Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [ProjectDiscovery](https://github.com/projectdiscovery) for `httpx`
- [TomNomNom](https://github.com/tomnomnom) for `gf`
- [lc](https://github.com/lc) for `gau`
- Community contributors for additional `gf` patterns

## Contact

For any issues, suggestions, or contributions, please open an issue on the repository or contact the maintainer at [betmen.dlx@gmail.com].
