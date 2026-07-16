# Web Vulnerability Scanner Pro v3.1

[**English Version**](README_EN.md) | [**中文版本**](README.md)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A powerful automated web application vulnerability scanner that supports 13 vulnerability detection types, featuring asynchronous concurrent architecture, a dynamic plugin system, a global cross-deduplication engine, a secondary verification mechanism, AI-powered false positive filtering, and multi-target batch scanning with enterprise-grade capabilities.

## Features

- **13 Vulnerability Detection Types**: Covers common web vulnerabilities including SQL Injection, XSS, CSRF, Command Injection, SSRF, XXE, and more
- **Asynchronous Concurrent Architecture**: High-performance asynchronous scanning based on aiohttp, supporting 50+ concurrent coroutines
- **Intelligent Web Crawler**: Supports JavaScript rendering, API endpoint discovery, and automatic form recognition
- **Dynamic Plugin System**: Supports custom detector plugins for flexible extension of detection capabilities
- **Automatic Login Support**: Supports Cookie authentication, Bearer Token, automatic form login, and OAuth2
- **Global Cross-Deduplication Engine**: Three-layer deduplication (Exact / Input Point / Root Cause) to effectively eliminate cross-detector duplicate reports
- **Secondary Verification Mechanism**: Reconfirms suspicious vulnerabilities using different payloads to reduce false positive rates
- **AI-Powered False Positive Filtering**: Integrates large language models to analyze vulnerability context and automatically identify obvious false positives (optional)
- **Intelligent Payload Generation**: Dynamically generates targeted test cases based on parameter type and context (optional)
- **Multi-Target Batch Scanning**: Supports loading multiple target URLs from a file with automatic task queue creation
- **Task Persistence**: Stores scan tasks and vulnerability data in SQLite, supporting resume from interruption
- **Multi-Format Reporting**: Automatically generates scan reports in HTML, JSON, and CSV formats
- **Proxy Support**: Compatible with HTTP/SOCKS proxies, can be used alongside tools such as Burp Suite

## Supported Vulnerability Detection Types

| Detection Type | Detector Class | Severity | Description |
|---------------|---------------|----------|-------------|
| SQL Injection | SQLInjectionDetector | High | Error-based, Boolean-based, Time-based, Union-based |
| XSS (Cross-Site Scripting) | XSSDetector | High | Reflected XSS, DOM-based XSS, Context analysis |
| CSRF (Cross-Site Request Forgery) | CSRFDetector | Medium | Missing CSRF tokens on forms, insufficient API endpoint protection |
| Command Injection | CommandInjectionDetector | High | OS command injection, DNS exfiltration, Time-based delay |
| SSRF (Server-Side Request Forgery) | SSRFDetector | High | Internal network access, Cloud metadata exposure |
| XXE (XML External Entity) | XXEDetector | High | File read, External entity injection |
| Directory Traversal | DirectoryTraversalDetector | High | Path traversal, Sensitive file access |
| File Upload | FileUploadDetector | High | Malicious file upload, Extension bypass, MIME manipulation |
| CORS Misconfiguration | CORSDetector | High/Medium | Cross-Origin Resource Sharing misconfiguration, Origin reflection |
| Sensitive File Disclosure | SensitiveFilesDetector | High/Medium | Public access to .env, .git, configuration files |
| Security Headers Missing | SecurityHeadersDetector | High/Medium | Missing HSTS, CSP, X-Frame-Options, etc. |
| Weak Password | WeakPasswordDetector | High | Common username/password combinations, default credentials |
| Open Redirect | OpenRedirectDetector | Medium | URL redirection to malicious sites, protocol-relative URL abuse |

## Architecture Evolution

### v3.0 Core Architecture
- Asynchronous concurrent crawler + 13 detectors + Plugin system + Automatic login

### v3.1 Enterprise-Grade Enhancements
| Module | Functionality | Description |
|--------|--------------|-------------|
| `dedup_engine.py` | Global Cross-Deduplication | Three-layer deduplication (L1 Exact / L2 Input Point / L3 Root Cause Merge), eliminating cross-detector duplicate reports |
| `verification.py` | Secondary Verification & Context Awareness | 7 parameter type inferences, independent verification strategies for SQL/XSS/Command Injection/Directory Traversal |
| `task_manager.py` | Multi-Target & Task Persistence | SQLite database, batch scanning, task status tracking, resume from interruption, historical query |
| `ai_analyzer.py` | AI Analysis Engine | LLM false positive filtering, intelligent payload generation, enhanced remediation recommendations (compatible with OpenAI / DeepSeek / Qwen) |

### v3.1.1 Security Hardening & Quality Optimization

A comprehensive code audit and four-phase improvement, totaling 22 optimizations:

**Security Fixes (Critical)**
- Fixed stored XSS in HTML reports (switched to Jinja2 autoescape for automatic escaping)
- Restored async HTTP SSL certificate verification (was globally disabled with `ssl=False`)
- Upgraded dependencies with known CVEs (requests/aiohttp/Jinja2/urllib3)
- Mitigated LLM prompt injection (field truncation + defense directives + data delimiter isolation)
- Tightened plugin loading whitelist (only accepts classes ending with Detector/Scanner)

**Architecture Optimization**
- Extracted `BaseDetector(ABC)` abstract base class, unifying `__init__`/`_deduplicate_vulns`/`_build_vuln` across 13 detectors, eliminating ~600 lines of duplicate code
- Fixed Logger singleton `__new__` signature crash, added `set_verbose()` for runtime log level switching
- Fixed synchronous HTTP calls blocking the event loop in async functions (added `_async_get()` compatibility method)
- Removed dead code `session_manager.py` (never referenced)
- Added `__init__.py` package files to normalize package structure

**Quality Improvements**
- Added 26 unit tests (BaseDetector/Logger/XSS escaping), configured pytest.ini and conftest.py
- Fixed 3 silent exception swallowing (`except Exception: pass` → with logging)
- Replaced 5 `print` calls with `logging` in main.py
- Rewrote report generator with Jinja2 templates, splitting 285-line f-string into template rendering
- Added context managers to HTTP utilities (`__enter__/__exit__` + `__aenter__/__aexit__`)

**Performance Optimization**
- LLM analysis result caching (avoids redundant calls for identical vulnerabilities)
- TaskManager switched from per-row INSERT to `executemany` batch insertion
- Crawler URL queue changed to `deque(maxlen=2000)`, `pop(0)` to `popleft()` (O(1))
- Rate limiter protected with `threading.Lock`/`asyncio.Lock` for thread/coroutine safety
- Cached `response.text` to local variables in detectors to avoid repeated decoding

## Installation

### Prerequisites

- Python 3.8 or higher
- Windows / Linux / macOS

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/bmslos/webjc-3.0.git
cd webjc-3.0

# Install dependencies
pip install -r requirements.txt

# Install AI analysis dependencies (optional, required only when AI features are enabled)
pip install openai

# Verify installation
python main.py --help
```

## Quick Start

### Basic Scanning

```bash
# Asynchronous scanning (recommended)
python main.py -t https://example.com

# Synchronous scanning (compatibility mode)
python main.py -t https://example.com --sync
```

### Scanning with Authentication

```bash
# Using Cookie authentication
python main.py -t https://example.com --cookie "session=abc123"

# Using Bearer Token
python main.py -t https://example.com --auth-token "your-token-here"

# Automatic login scanning
python main.py -t https://example.com \
  --auto-login \
  --login-url https://example.com/login \
  --username admin \
  --password 123456
```

### Multi-Target Batch Scanning

```bash
# Load target URLs from file (one URL per line)
python main.py -T targets.txt

# Example targets.txt:
# https://site1.com
# https://site2.com
# https://site3.com
```

### Enabling AI Analysis

```bash
# Using OpenAI GPT-4
python main.py -t https://example.com \
  --enable-ai \
  --ai-api-key "sk-your-key"

# Using environment variables (recommended)
export LLM_API_KEY="sk-your-key"
python main.py -t https://example.com --enable-ai

# Using DeepSeek model
python main.py -t https://example.com \
  --enable-ai \
  --ai-api-base "https://api.deepseek.com/v1" \
  --ai-model "deepseek-chat"

# Using Qwen (Tongyi Qianwen)
python main.py -t https://example.com \
  --enable-ai \
  --ai-api-base "https://dashscope.aliyuncs.com/compatible-mode/v1" \
  --ai-model "qwen-turbo"
```

### Advanced Configuration

```bash
# Custom concurrency and crawling parameters
python main.py -t https://example.com \
  --threads 20 \
  --max-pages 500 \
  --rate-limit 0.1

# Using a proxy
python main.py -t https://example.com \
  --proxy http://127.0.0.1:8080

# Disable crawler, scan only the target URL
python main.py -t https://example.com/api/v1 --no-crawler

# Disable deduplication and verification (fast scan mode)
python main.py -t https://example.com --no-dedup --no-verify

# Generate JSON format report
python main.py -t https://example.com --report-format json

# Verbose output mode
python main.py -t https://example.com --verbose
```

### Task Management

```bash
# List all scan tasks
python main.py --list-tasks

# View task statistics
python main.py --task-stats

# Resume interrupted scan tasks
python main.py --resume
```

## Command-Line Arguments

### Target Arguments

| Argument | Shorthand | Description |
|----------|-----------|-------------|
| `--target` | `-t` | Scan target URL (single target) |
| `--targets` | `-T` | Scan target file path (multi-target, one URL per line) |

### Scan Configuration

| Argument | Shorthand | Default | Description |
|----------|-----------|---------|-------------|
| `--timeout` | - | 15 | HTTP request timeout (seconds) |
| `--threads` | `-n` | 10 | Number of scan threads |
| `--max-pages` | `-m` | 200 | Maximum pages for crawler |
| `--rate-limit` | `-r` | 0.1 | Request interval (seconds) |

### Authentication Options

| Argument | Shorthand | Description |
|----------|-----------|-------------|
| `--cookie` | `-c` | Authentication Cookie (format: "name1=value1;name2=value2") |
| `--header` | `-H` | Custom request header (format: "Header: Value"), can be used multiple times |
| `--auth-token` | - | Bearer Token authentication |
| `--auto-login` | - | Enable automatic login |
| `--login-url` | - | Login page URL |
| `--username` | `-u` | Login username |
| `--password` | `-p` | Login password |

### Feature Toggles

| Argument | Description |
|----------|-------------|
| `--proxy` | HTTP proxy address |
| `--no-crawler` | Disable crawler, scan only target URL |
| `--sync` | Use synchronous mode |
| `--no-async` | Disable asynchronous mode |
| `--no-dedup` | Disable global cross-deduplication |
| `--no-verify` | Disable secondary verification |
| `--enable-ai` | Enable AI analysis (false positive filtering + intelligent payload) |
| `--ai-api-key` | LLM API key |
| `--ai-api-base` | LLM API base URL |
| `--ai-model` | LLM model name (default: gpt-4o-mini) |
| `--plugin-dir` | Plugin directory path |
| `--list-plugins` | List all available plugins |

### Task Management

| Argument | Description |
|----------|-------------|
| `--list-tasks` | List all scan tasks |
| `--task-stats` | Display task statistics |
| `--resume` | Resume interrupted scan tasks |

### Output Configuration

| Argument | Shorthand | Default | Description |
|----------|-----------|---------|-------------|
| `--output` | `-o` | reports | Report output directory |
| `--report-format` | `-f` | html | Report format (html/json/csv) |
| `--verbose` | `-v` | - | Verbose output mode |
| `--quiet` | `-q` | - | Quiet mode, only output report path |

## Scanning Pipeline

The scanning process executes in the following order:

```
1. Web Crawling         → Discover URLs, forms, parameters, API endpoints
2. Vulnerability Scan   → 13+ detectors execute concurrently
3. Global Cross-Dedup   → Three-layer deduplication (Exact / Input Point / Root Cause Merge)
4. Secondary Verify     → Reconfirm suspicious vulnerabilities, calculate confidence scores
5. AI False Positive    → LLM analyzes context, filters obvious false positives (optional)
6. Report Generation    → Multi-format output in HTML / JSON / CSV
```

## Project Structure

```
webjc-3.0/
├── main.py                      # Main entry point
├── requirements.txt             # Python dependencies
├── README.md                    # Project Documentation (Chinese)
├── README_EN.md                 # Project Documentation (English)
├── LICENSE                      # MIT License
├── .gitignore                   # Git ignore configuration
│
├── core/                        # Core modules
│   ├── config.py                # Configuration file
│   ├── scanner.py               # Scan engine (integrated with dedup / verification / AI pipeline)
│   ├── crawler.py               # Web crawler
│   ├── plugin_manager.py        # Plugin manager
│   ├── dedup_engine.py          # Global cross-deduplication engine (v3.1 new)
│   ├── verification.py          # Secondary verification & context awareness (v3.1 new)
│   ├── task_manager.py          # Multi-target task manager (v3.1 new)
│   ├── ai_analyzer.py           # AI analysis engine (v3.1 new)
│   │
│   ├── detectors/               # Vulnerability detectors
│   │   ├── __init__.py          # Package init
│   │   ├── base.py              # Detector abstract base class (v3.1.1 new)
│   │   ├── sqli.py              # SQL Injection detector
│   │   ├── xss.py               # XSS detector
│   │   ├── csrf.py              # CSRF detector
│   │   ├── command_injection.py # Command Injection detector
│   │   ├── ssrf.py              # SSRF detector
│   │   ├── xxe.py               # XXE detector
│   │   ├── directory_traversal.py # Directory Traversal detector
│   │   ├── file_upload.py       # File Upload detector
│   │   ├── cors.py              # CORS detector
│   │   ├── sensitive_files.py   # Sensitive Files detector
│   │   ├── security_headers.py  # Security Headers detector
│   │   ├── weak_password.py     # Weak Password detector
│   │   └── open_redirect.py     # Open Redirect detector
│   │
│   └── utils/                   # Utility modules
│       ├── __init__.py          # Package init
│       ├── http.py              # HTTP client (sync / async)
│       ├── logger.py            # Logger
│       └── report.py            # Report generator
│
├── data/                        # Data storage (v3.1 new)
│   └── scan_tasks.db            # SQLite task database
│
├── plugins/                     # User plugin directory
│   ├── __init__.py              # Package init
│   └── xxe_detector.py          # XXE detector example plugin (thin wrapper)
│
├── pytest.ini                   # pytest configuration (v3.1.1 new)
│
└── tests/                       # Unit tests
    ├── __init__.py              # Package init
    ├── conftest.py              # pytest shared fixtures (v3.1.1 new)
    ├── test_new_modules.py      # Tests for v3.1 new modules
    ├── test_base_detector.py    # BaseDetector unit tests (v3.1.1 new)
    ├── test_logger.py           # Logger unit tests (v3.1.1 new)
    └── test_report.py           # Report XSS escaping tests (v3.1.1 new)
```

## Custom Plugin Development

### Creating a Plugin

Create a Python file in the `plugins/` directory implementing a detector class:

```python
# plugins/my_detector.py
from typing import Dict, List
from core.detectors.base import BaseDetector


class MyDetector(BaseDetector):
    """Custom detector example"""

    def __init__(self, target: str, http, urls=None, forms=None, **kwargs):
        super().__init__(target, http, urls=urls, forms=forms, **kwargs)
        self.name = "My Detector"

    def scan(self) -> List[Dict]:
        """Execute scan and return vulnerability list (base class provides dedup and vuln construction)"""
        vulnerabilities = []

        # Your detection logic
        for url in self.urls:
            response = self.http.get(url)
            if self._check_vulnerability(response):
                # Use base class _build_vuln to construct standard vulnerability dict
                vulnerabilities.append(self._build_vuln(
                    vuln_type='Vulnerability Type',
                    severity='High',  # Critical / High / Medium / Low / Info
                    url=url,
                    parameter='Parameter Name',
                    payload='Payload used',
                    description='Vulnerability description',
                    recommendation='Remediation recommendation'
                ))

        # Base class _deduplicate_vulns handles deduplication
        return self._deduplicate_vulns(vulnerabilities)

    def _check_vulnerability(self, response) -> bool:
        """Check if the response indicates a vulnerability"""
        # Implement your detection logic
        return False
```

### Using Plugins

```bash
# Automatically load all plugins from the plugins/ directory
python main.py -t https://example.com

# Specify a custom plugin directory
python main.py -t https://example.com --plugin-dir /path/to/plugins

# List all available plugins
python main.py -t https://example.com --list-plugins
```

## Report Examples

### HTML Report

After scanning completes, a well-formatted HTML report is generated in the output directory:

```
reports/
└── scan_report_20260409_162519.html
```

The report includes:
- Scan overview (target, time, statistics)
- Vulnerability severity distribution chart
- Detailed information for each vulnerability
- Remediation recommendations

### JSON Report

```bash
python main.py -t https://example.com --report-format json
```

Generates machine-readable JSON reports for integration and automated processing.

## Development Guide

### Code Style

This project uses [Black](https://github.com/psf/black) for code formatting:

```bash
# Install Black
pip install black

# Format code
black .

# Check code style
flake8 .
```

### Running Tests

```bash
# Run all unit tests
pytest

# Run a specific test file
pytest tests/test_base_detector.py -v
```

### Adding a New Detector

1. Create a new file under `core/detectors/`
2. Inherit from `BaseDetector` base class and implement the `scan()` method (automatically gains deduplication and vulnerability construction)
3. Add configuration in `VULN_CONFIG` within `core/config.py`
4. Register in `detector_mapping` within `core/scanner.py`

Refer to `core/detectors/base.py` for the base class interface, and `core/detectors/sqli.py` as a complete example.

## Important Notes

- **Legal Use**: Only scan targets you are authorized to test. Scanning unauthorized websites may be illegal.
- **Rate Limiting**: Use the `--rate-limit` parameter to control request frequency and avoid overwhelming the target.
- **Production Environments**: Thoroughly test and assess potential impact before scanning in production.
- **False Positives**: Automated scanning tools may produce false positives. Manual verification of discovered vulnerabilities is recommended.
- **AI Features**: AI analysis is optional. When no API Key is configured, the system automatically falls back to the rule engine without affecting basic scanning functionality.

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

We welcome Issues and Pull Requests!

1. Fork this repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Support

- Submit an [Issue](https://github.com/bmslos/webjc-3.0/issues)
- Participate in [Discussions](https://github.com/bmslos/webjc-3.0/discussions)

## Changelog

### v3.1.1 (2026-07-16)

**Security Hardening & Quality Optimization (22 improvements)**

Security Fixes:
- Fixed stored XSS in HTML reports (switched to Jinja2 autoescape)
- Restored async HTTP SSL certificate verification (was globally disabled with `ssl=False`)
- Upgraded dependencies with known CVEs (requests/aiohttp/Jinja2/urllib3)
- Mitigated LLM prompt injection (field truncation + defense directives + delimiter isolation)
- Tightened plugin loading whitelist (Detector/Scanner suffix only)

Architecture Optimization:
- Extracted `BaseDetector(ABC)` base class, eliminating ~600 lines of duplicate code across 13 detectors
- Fixed Logger singleton `__new__` crash, added `set_verbose()` method
- Fixed synchronous HTTP calls blocking event loop in async functions
- Removed dead code `session_manager.py` and redundant dependency `asyncio-mqtt`
- Added `__init__.py` package files to normalize package structure

Quality Improvements:
- Added 26 unit tests, configured pytest.ini and conftest.py
- Fixed 3 silent exception swallowing, replaced 5 `print` calls with `logging`
- Rewrote report generator with Jinja2 templates, splitting 285-line function
- Added context managers to HTTP utilities (`__enter__/__exit__` + `__aenter__/__aexit__`)

Performance Optimization:
- LLM analysis result caching (avoids redundant calls)
- TaskManager batch INSERT via `executemany`
- Crawler URL queue changed to `deque(maxlen=2000)`, `pop(0)` to `popleft()` (O(1))
- Rate limiter protected with `threading.Lock`/`asyncio.Lock`

### v3.1 (2026-05-14)

**Enterprise-Grade Enhancements**
- Added global cross-deduplication engine (three-layer deduplication: exact / input point / root cause merge)
- Added secondary verification module (parameter type inference, multi-strategy verification, confidence scoring)
- Added multi-target batch scanning and task persistence (SQLite database, resume from interruption)
- Added AI analysis engine (LLM false positive filtering, intelligent payload generation, enhanced remediation recommendations)
- Added task management commands (`--list-tasks`, `--task-stats`, `--resume`)
- Updated scan engine with integrated dedup / verification / AI post-processing pipeline
- Updated main entry point to support multi-target files and AI configuration parameters

### v3.0 (2026-04-09)

- Added 13 vulnerability detectors
- Asynchronous concurrent architecture support
- Dynamic plugin system
- Automatic login and session management
- Multi-format report generation
- Proxy support

---

Made with ❤️ by bmslos
