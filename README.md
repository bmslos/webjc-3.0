# Web Vulnerability Scanner Pro

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Async](https://img.shields.io/badge/Async-Supported-brightgreen.svg)](https://docs.aiohttp.org/)
[![Playwright](https://img.shields.io/badge/Playwright-Optional-orange.svg)](https://playwright.dev/)

A powerful, extensible, and async-capable web application vulnerability scanner with plugin system, automatic login, and JavaScript rendering support.

## ✨ Features

- 🚀 **Async Architecture** - 10-50x performance improvement with aiohttp
- 🕷️ **JavaScript Rendering** - Crawl SPAs with Playwright support
- 🔌 **Plugin System** - Dynamic vulnerability detector plugins
- 🔐 **Auto Login** - Automatic authentication with session management
- 🌐 **Proxy Support** - Works with Burp Suite and other proxies
- 📊 **Modern Reports** - Beautiful HTML/JSON/CSV reports
- 🎯 **13+ Vulnerability Types** - Comprehensive coverage
- ⚙️ **Configuration Management** - Centralized and flexible config

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/your-username/webjc-pro.git
cd webjc-pro

# Install dependencies
pip install -r requirements.txt

# Optional: Install Playwright browsers for JS rendering
playwright install chromium
```

## 🚀 Quick Start

### Basic Scan

```bash
# Simple async scan
python main.py -t http://example.com

# Scan with custom report format
python main.py -t http://example.com -f json -o ./reports
```

### Authenticated Scan

```bash
# With cookie
python main.py -t http://example.com -c "session=abc123"

# With bearer token
python main.py -t http://example.com --auth-token "your-jwt-token"

# Auto login
python main.py -t http://example.com \
  --auto-login \
  --login-url http://example.com/login \
  --username admin \
  --password 123456
```

### Advanced Usage

```bash
# With proxy (Burp Suite)
python main.py -t http://example.com --proxy http://127.0.0.1:8080

# High concurrency scan
python main.py -t http://example.com \
  --threads 20 \
  --max-pages 500 \
  --rate-limit 0.05

# Disable crawler, scan single URL
python main.py -t http://example.com/api/endpoint --no-crawler

# Sync mode (compatibility)
python main.py -t http://example.com --sync
```

## 📖 Documentation

- [**Usage Guide**](USAGE_GUIDE.md) - Complete usage guide and best practices
- [**Comparison**](COMPARISON.md) - Detailed comparison with original version
- [**Upgrade Summary**](UPGRADE_SUMMARY.md) - What's new in this version

## 🎯 CLI Parameters

| Parameter | Short | Description | Default |
|-----------|-------|-------------|---------|
| --target | -t | Target URL (required) | - |
| --timeout | -T | HTTP timeout (seconds) | 15 |
| --threads | -n | Number of threads | 10 |
| --max-pages | -m | Max pages to crawl | 200 |
| --rate-limit | -r | Request interval (seconds) | 0.1 |
| --cookie | -c | Authentication cookie | - |
| --auth-token | - | Bearer token | - |
| --auto-login | - | Enable auto login | False |
| --login-url | - | Login page URL | - |
| --username | -u | Login username | - |
| --password | -p | Login password | - |
| --proxy | - | HTTP proxy address | - |
| --no-crawler | - | Disable crawler | False |
| --sync | - | Use sync mode | False |
| --output | -o | Report output dir | reports |
| --report-format | -f | Report format (html/json/csv) | html |
| --verbose | -v | Verbose output | False |
| --quiet | -q | Quiet mode | False |

## 🔌 Plugin System

### Creating a Custom Detector

Create a file in `plugins/` directory:

```python
# plugins/my_detector.py
from typing import Dict, List, Optional
from core.utils.logger import Logger

class MyDetector:
    def __init__(self, target, http, urls=None, forms=None, **kwargs):
        self.name = "My Custom Detector"
        self.target = target
        self.http = http
        self.urls = urls or [target]
        self.forms = forms or []
        self.logger = Logger()
    
    def scan(self) -> List[Dict]:
        vulnerabilities = []
        # Your detection logic here
        return vulnerabilities
```

The scanner automatically discovers and loads all plugins!

## 🛡️ Supported Vulnerability Types

- SQL Injection (Error-based, Boolean-blind, Time-blind)
- Cross-Site Scripting (XSS) - Reflected & Stored
- Cross-Site Request Forgery (CSRF)
- Server-Side Request Forgery (SSRF)
- XML External Entity (XXE)
- Command Injection
- Directory Traversal
- File Upload Vulnerabilities
- CORS Misconfiguration
- Security Headers Missing
- Weak Passwords
- Open Redirect
- Sensitive Files Exposure

## 📊 Project Structure

```
webjc-pro/
├── main.py                      # Main entry point
├── requirements.txt             # Python dependencies
├── .gitignore                   # Git ignore rules
├── README.md                    # This file
├── USAGE_GUIDE.md               # Usage guide
├── COMPARISON.md                # Version comparison
├── UPGRADE_SUMMARY.md           # Upgrade summary
│
├── core/
│   ├── config.py                # Centralized configuration
│   ├── scanner.py               # Enhanced scanner engine
│   ├── crawler.py               # Web crawler with JS support
│   ├── plugin_manager.py        # Dynamic plugin loader
│   ├── session_manager.py       # Session & auth management
│   │
│   ├── detectors/               # Built-in detectors
│   │   └── sqli.py              # SQL injection detector
│   │
│   └── utils/
│       ├── http.py              # Sync + Async HTTP clients
│       ├── logger.py            # Logging utility
│       └── report.py            # Report generator
│
└── plugins/                     # Plugin directory
    └── xxe_detector.py          # Example plugin
```

## 🔧 Configuration

All configurations are centralized in `core/config.py`:

- `HTTP_CONFIG` - Timeout, retries, proxy, rate limiting
- `ASYNC_CONFIG` - Concurrency settings
- `CRAWLER_CONFIG` - Crawling depth, JS rendering
- `AUTH_CONFIG` - Auto login, token refresh
- `VULN_CONFIG` - Payloads and patterns for each vulnerability type
- `PLUGIN_CONFIG` - Enable/disable plugins

## ⚠️ Disclaimer

This tool is intended for **educational and authorized security testing** purposes only. Always obtain proper authorization before scanning any website you don't own. The authors are not responsible for any misuse or damage caused by this program.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Original version: [webjc](../webjc) - A simple web vulnerability scanner
- [aiohttp](https://docs.aiohttp.org/) - Async HTTP client
- [Playwright](https://playwright.dev/) - Browser automation
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) - HTML parser
- [requests](https://docs.python-requests.org/) - HTTP library

## 📧 Contact

For questions, issues, or support:
- Open an issue on GitHub
- Check the documentation
- Review existing issues

---

**Made with ❤️ for security researchers and developers**
