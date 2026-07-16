# Web Vulnerability Scanner Pro v3.1.1

[**English Version**](README_EN.md) | [**中文版本**](README.md)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A powerful automated web application vulnerability scanner supporting 13 vulnerability detection types, featuring asynchronous concurrent architecture, dynamic plugin system, global cross-deduplication engine, secondary verification mechanism, AI-powered false positive filtering, and multi-target batch scanning with enterprise-grade capabilities.

## Core Features

| Category | Feature |
|----------|---------|
| **Vulnerability Detection** | SQL Injection, XSS, CSRF, Command Injection, SSRF, XXE, Directory Traversal, File Upload, and more (13 types) |
| **High-Performance Architecture** | Asynchronous concurrent scanning based on aiohttp, supporting 50+ coroutines |
| **Intelligent Crawler** | JavaScript rendering, API endpoint discovery, automatic form recognition |
| **False Positive Control** | Three-layer deduplication (Exact/Input Point/Root Cause) + Secondary Verification + AI Filtering |
| **Task Management** | SQLite persistence, multi-target batch scanning, resume from interruption |
| **Report Output** | HTML/JSON/CSV multi-format, XSS protection |
| **Extensibility** | Dynamic plugin system for custom detectors |

## Supported Vulnerabilities

| Vulnerability Type | Severity | Detection Method |
|--------------------|----------|------------------|
| SQL Injection | High | Error-based, Boolean-based, Time-based, Union-based |
| XSS (Cross-Site Scripting) | High | Reflected, DOM-based, Context analysis |
| Command Injection | High | OS command injection, DNS exfiltration, Time-based delay |
| SSRF | High | Internal network access, Cloud metadata exposure |
| XXE | High | XML external entity injection, File read |
| Directory Traversal | High | Path traversal, Sensitive file access |
| File Upload | High | Malicious file upload, Extension bypass, MIME manipulation |
| CORS Misconfiguration | High/Medium | Origin reflection, Misconfiguration |
| Sensitive File Disclosure | High/Medium | Public access to .env, .git, config files |
| Security Headers Missing | High/Medium | Missing HSTS, CSP, X-Frame-Options |
| CSRF | Medium | Missing Token, Insufficient API protection |
| Weak Password | High | Common username/password combinations |
| Open Redirect | Medium | URL redirection to malicious sites |

## Scanning Pipeline

```
Crawl → Scan → Deduplicate → Verify → AI Filter → Report
```

1. **Crawl**: Discover URLs, forms, parameters, API endpoints
2. **Scan**: 13+ detectors execute concurrently
3. **Deduplicate**: Three-layer cross-deduplication eliminates duplicate reports
4. **Verify**: Reconfirm suspicious vulnerabilities, calculate confidence scores
5. **AI Filter**: LLM analyzes context, filters obvious false positives (optional)
6. **Report**: Multi-format output (HTML/JSON/CSV)

## Quick Start

### Installation

```bash
git clone https://github.com/bmslos/webjc-3.0.git
cd webjc-3.0
pip install -r requirements.txt
python main.py --help
```

### Basic Scanning

```bash
python main.py -t https://example.com
```

### Scanning with Authentication

```bash
python main.py -t https://example.com --cookie "session=abc123"
python main.py -t https://example.com --auth-token "your-token"
```

### Multi-Target Batch Scanning

```bash
python main.py -T targets.txt
```

### Enable AI Analysis

```bash
python main.py -t https://example.com --enable-ai --ai-api-key "sk-your-key"
```

### Task Management

```bash
python main.py --list-tasks
python main.py --task-stats
python main.py --resume
```

## Command-Line Arguments

| Argument | Shorthand | Description |
|----------|-----------|-------------|
| `--target` | `-t` | Scan target URL |
| `--targets` | `-T` | Multi-target file path |
| `--threads` | `-n` | Number of threads (default: 10) |
| `--max-pages` | `-m` | Maximum pages to crawl (default: 200) |
| `--rate-limit` | `-r` | Request interval (default: 0.1s) |
| `--cookie` | `-c` | Authentication Cookie |
| `--auth-token` | - | Bearer Token |
| `--proxy` | - | HTTP proxy address |
| `--enable-ai` | - | Enable AI analysis |
| `--no-dedup` | - | Disable deduplication |
| `--no-verify` | - | Disable secondary verification |
| `--no-crawler` | - | Disable crawler |
| `--report-format` | `-f` | Report format (html/json/csv) |
| `--verbose` | `-v` | Verbose output |
| `--list-plugins` | - | List available plugins |

## Project Structure

```
webjc-3.0/
├── main.py              # Main entry point
├── requirements.txt     # Dependency list
├── LICENSE              # MIT License
├── core/                # Core modules
│   ├── scanner.py       # Scan engine
│   ├── crawler.py       # Web crawler
│   ├── dedup_engine.py  # Global deduplication engine
│   ├── verification.py  # Secondary verification
│   ├── task_manager.py  # Task manager
│   ├── ai_analyzer.py   # AI analysis engine
│   ├── plugin_manager.py # Plugin manager
│   ├── config.py        # Configuration
│   ├── detectors/       # Vulnerability detectors (13 types)
│   │   ├── base.py      # Detector base class
│   │   └── ...
│   └── utils/           # Utility modules
│       ├── http.py      # HTTP client
│       ├── logger.py    # Logger
│       └── report.py    # Report generator
├── plugins/             # User plugin directory
├── tests/               # Unit tests (26 tests)
└── pytest.ini           # pytest configuration
```

## Changelog

### v3.1.1 (2026-07-16)

**Security Fixes**
- Fixed stored XSS in HTML reports (Jinja2 autoescape)
- Restored async HTTP SSL certificate verification
- Upgraded dependencies with known CVEs
- LLM prompt injection mitigation
- Tightened plugin loading whitelist

**Architecture Optimization**
- Extracted `BaseDetector(ABC)` base class, eliminating ~600 lines of duplicate code
- Fixed Logger singleton crash
- Fixed synchronous HTTP blocking in async functions
- Removed dead code `session_manager.py`

**Quality Improvements**
- Added 26 unit tests
- Fixed 3 silent exception swallowing
- Report generator rewritten with Jinja2 templates
- HTTP utilities added context managers

**Performance Optimization**
- LLM analysis result caching
- TaskManager batch insertion
- Crawler queue changed to `deque` (O(1))
- Rate limiter thread safety

### v3.1 (2026-05-14)

- Global cross-deduplication engine
- Secondary verification & context awareness
- Multi-target batch scanning & task persistence
- AI analysis engine (OpenAI/DeepSeek/Qwen compatible)
- Task management commands (`--list-tasks`, `--task-stats`, `--resume`)

### v3.0 (2026-04-09)

- 13 vulnerability detectors
- Asynchronous concurrent architecture
- Dynamic plugin system
- Automatic login support
- Multi-format report generation

## Plugin Development

Create custom detectors by inheriting from `BaseDetector`:

```python
from core.detectors.base import BaseDetector

class MyDetector(BaseDetector):
    def scan(self):
        vulnerabilities = []
        for url in self.urls:
            response = self.http.get(url)
            if self._check_vuln(response):
                vulnerabilities.append(self._build_vuln(
                    vuln_type='Vulnerability Type',
                    severity='High',
                    url=url,
                    parameter='Parameter',
                    payload='payload',
                    description='Description',
                    recommendation='Remediation'
                ))
        return self._deduplicate_vulns(vulnerabilities)
```

## Important Notes

- **Legal Use**: Only scan targets you are authorized to test. Unauthorized scanning may be illegal.
- **Rate Limiting**: Use `--rate-limit` to control request frequency.
- **False Positives**: Automated scanning may produce false positives. Manual verification is recommended.
- **AI Features**: When no API Key is configured, the system automatically falls back to rule engine.

## License

[MIT License](LICENSE)

## Contributing

Welcome to submit Issues and Pull Requests!

---

Made with ❤️ by bmslos