# Web Vulnerability Scanner Pro v3.0

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

一款功能强大的Web应用漏洞自动化扫描工具,支持13种漏洞检测类型,具备异步并发架构和动态插件系统。

## 特性

- **13种漏洞检测**: 涵盖SQL注入、XSS、CSRF、命令注入、SSRF、XXE等常见Web漏洞
- **异步并发架构**: 基于aiohttp的高性能异步扫描,支持20+并发协程
- **智能网站爬虫**: 支持JavaScript渲染、API端点发现、表单自动识别
- **动态插件系统**: 支持自定义检测器插件,灵活扩展检测能力
- **自动登录支持**: 支持Cookie认证、Bearer Token、表单自动登录
- **多格式报告**: 自动生成HTML、JSON、CSV格式的扫描报告
- **代理支持**: 兼容HTTP/SOCKS代理,可与Burp Suite等工具配合使用

## 支持的漏洞检测类型

| 检测类型 | 检测器类 | 严重程度 | 描述 |
|---------|---------|---------|------|
| SQL注入 | SQLInjectionDetector | 高危 | 错误回显、布尔盲注、时间盲注、Union注入 |
| XSS跨站脚本 | XSSDetector | 高危 | 反射型XSS、DOM型XSS、上下文分析 |
| CSRF跨站请求伪造 | CSRFDetector | 中危 | 表单CSRF Token缺失、API端点保护不足 |
| 命令注入 | CommandInjectionDetector | 高危 | 系统命令注入、DNS外带、时间延迟 |
| SSRF | SSRFDetector | 高危 | 服务端请求伪造、内网访问、云元数据泄露 |
| XXE | XXEDetector | 高危 | XML外部实体注入、文件读取 |
| 目录遍历 | DirectoryTraversalDetector | 高危 | 路径遍历、敏感文件读取 |
| 文件上传 | FileUploadDetector | 高危 | 恶意文件上传、扩展名绕过、MIME操纵 |
| CORS错误配置 | CORSDetector | 高危/中危 | 跨域资源共享配置错误、Origin反射 |
| 敏感文件泄露 | SensitiveFilesDetector | 高危/中危 | .env、.git、配置文件公开访问 |
| 安全头缺失 | SecurityHeadersDetector | 高危/中危 | HSTS、CSP、X-Frame-Options等缺失 |
| 弱密码 | WeakPasswordDetector | 高危 | 常见用户名密码组合、默认凭证 |
| 开放重定向 | OpenRedirectDetector | 中危 | URL重定向到恶意网站、协议相对URL |

## 安装

### 环境要求

- Python 3.8 或更高版本
- Windows / Linux / macOS

### 安装步骤

```bash
# 克隆仓库
git clone https://github.com/bmslos/webjc-3.0.git
cd webjc-3.0

# 安装依赖
pip install -r requirements.txt

# 验证安装
python main.py --help
```

## 快速开始

### 基础扫描

```bash
# 异步扫描(推荐)
python main.py -t https://example.com

# 同步扫描(兼容模式)
python main.py -t https://example.com --sync
```

### 带认证扫描

```bash
# 使用Cookie认证
python main.py -t https://example.com --cookie "session=abc123"

# 使用Bearer Token
python main.py -t https://example.com --auth-token "your-token-here"

# 自动登录扫描
python main.py -t https://example.com \
  --auto-login \
  --login-url https://example.com/login \
  --username admin \
  --password 123456
```

### 高级配置

```bash
# 自定义并发和爬取参数
python main.py -t https://example.com \
  --threads 20 \
  --max-pages 500 \
  --rate-limit 0.1

# 使用代理
python main.py -t https://example.com \
  --proxy http://127.0.0.1:8080

# 禁用爬虫,仅扫描单个URL
python main.py -t https://example.com/api/v1 --no-crawler

# 生成JSON格式报告
python main.py -t https://example.com --report-format json

# 详细输出模式
python main.py -t https://example.com --verbose
```

## 命令行参数

### 必需参数

| 参数 | 简写 | 说明 |
|-----|------|------|
| `--target` | `-t` | 扫描目标URL |

### 扫描配置

| 参数 | 简写 | 默认值 | 说明 |
|-----|------|--------|------|
| `--timeout` | `-T` | 15 | HTTP请求超时时间(秒) |
| `--threads` | `-n` | 10 | 扫描线程数 |
| `--max-pages` | `-m` | 200 | 爬虫最大爬取页面数 |
| `--rate-limit` | `-r` | 0.1 | 请求间隔(秒) |

### 认证选项

| 参数 | 简写 | 说明 |
|-----|------|------|
| `--cookie` | `-c` | 认证Cookie(格式: "name1=value1;name2=value2") |
| `--header` | `-H` | 自定义请求头(格式: "Header: Value"),可多次使用 |
| `--auth-token` | - | Bearer Token认证 |
| `--auto-login` | - | 启用自动登录 |
| `--login-url` | - | 登录页面URL |
| `--username` | `-u` | 登录用户名 |
| `--password` | `-p` | 登录密码 |

### 功能开关

| 参数 | 说明 |
|-----|------|
| `--proxy` | HTTP代理地址 |
| `--no-crawler` | 禁用爬虫功能,仅扫描目标URL |
| `--sync` | 使用同步模式 |
| `--no-async` | 禁用异步模式 |
| `--plugin-dir` | 插件目录路径 |
| `--list-plugins` | 列出所有可用插件 |

### 输出配置

| 参数 | 简写 | 默认值 | 说明 |
|-----|------|--------|------|
| `--output` | `-o` | reports | 报告输出目录 |
| `--report-format` | `-f` | html | 报告格式(html/json/csv) |
| `--verbose` | `-v` | - | 详细输出模式 |
| `--quiet` | `-q` | - | 静默模式,仅输出报告路径 |

## 项目结构

```
webjc-3.0/
├── main.py                      # 主入口文件
├── requirements.txt             # Python依赖
├── README.md                    # 项目说明
├── LICENSE                      # MIT许可证
├── .gitignore                   # Git忽略配置
│
├── core/                        # 核心模块
│   ├── config.py                # 配置文件(480行)
│   ├── scanner.py               # 扫描引擎(414行)
│   ├── crawler.py               # 网站爬虫(393行)
│   ├── plugin_manager.py        # 插件管理器
│   ├── session_manager.py       # 会话管理器
│   │
│   ├── detectors/               # 漏洞检测器
│   │   ├── sqli.py              # SQL注入检测器
│   │   ├── xss.py               # XSS跨站脚本检测器
│   │   ├── csrf.py              # CSRF检测器
│   │   ├── command_injection.py # 命令注入检测器
│   │   ├── ssrf.py              # SSRF检测器
│   │   ├── xxe.py               # XXE检测器
│   │   ├── directory_traversal.py # 目录遍历检测器
│   │   ├── file_upload.py       # 文件上传检测器
│   │   ├── cors.py              # CORS检测器
│   │   ├── sensitive_files.py   # 敏感文件检测器
│   │   ├── security_headers.py  # 安全头检测器
│   │   ├── weak_password.py     # 弱密码检测器
│   │   └── open_redirect.py     # 开放重定向检测器
│   │
│   └── utils/                   # 工具模块
│       ├── http.py              # HTTP客户端(同步/异步)
│       ├── logger.py            # 日志记录器
│       └── report.py            # 报告生成器
│
└── plugins/                     # 用户插件目录
    └── xxe_detector.py          # XXE检测器示例插件
```

## 自定义插件开发

### 创建插件

在 `plugins/` 目录下创建Python文件,实现检测器类:

```python
# plugins/my_detector.py
from typing import Dict, List, Optional
from core.utils.logger import Logger


class MyDetector:
    """自定义检测器示例"""
    
    def __init__(self, target: str, http, urls=None, forms=None, **kwargs):
        self.name = "我的检测器"
        self.target = target
        self.http = http
        self.urls = urls or [target]
        self.forms = forms or []
        self.logger = Logger()
    
    def scan(self) -> List[Dict]:
        """执行扫描,返回漏洞列表"""
        vulnerabilities = []
        
        # 你的检测逻辑
        for url in self.urls:
            response = self.http.get(url)
            if self._check_vulnerability(response):
                vulnerabilities.append({
                    'type': '漏洞类型',
                    'severity': '严重程度',  # 严重/高危/中危/低危/信息
                    'url': url,
                    'parameter': '参数名',
                    'method': 'GET',
                    'payload': '使用的payload',
                    'description': '漏洞描述',
                    'recommendation': '修复建议'
                })
        
        return vulnerabilities
    
    def _check_vulnerability(self, response) -> bool:
        """检查是否存在漏洞"""
        # 实现你的检测逻辑
        return False
```

### 使用插件

```bash
# 自动加载plugins/目录下的所有插件
python main.py -t https://example.com

# 指定自定义插件目录
python main.py -t https://example.com --plugin-dir /path/to/plugins

# 列出所有可用插件
python main.py -t https://example.com --list-plugins
```

## 报告示例

### HTML报告

扫描完成后,会在输出目录生成美观的HTML报告:

```
reports/
└── scan_report_20260409_162519.html
```

报告包含:
- 扫描概览(目标、时间、统计数据)
- 漏洞严重程度分布图
- 每个漏洞的详细信息
- 修复建议

### JSON报告

```bash
python main.py -t https://example.com --report-format json
```

生成机器可读的JSON格式报告,便于集成和自动化处理。

## 开发指南

### 代码风格

本项目使用 [Black](https://github.com/psf/black) 进行代码格式化:

```bash
# 安装Black
pip install black

# 格式化代码
black .

# 检查代码风格
flake8 .
```

### 运行测试

```bash
# 运行单元测试
pytest tests/

# 运行集成测试
pytest tests/integration/
```

### 添加新的检测器

1. 在 `core/detectors/` 下创建新文件
2. 实现检测器类,遵循标准接口
3. 在 `core/config.py` 的 `VULN_CONFIG` 中添加配置
4. 在 `core/scanner.py` 的 `detector_mapping` 中注册

参考 `core/detectors/sqli.py` 作为模板。

## 注意事项

- **合法使用**: 仅对你拥有授权的目标进行扫描,未经授权扫描他人网站可能违法
- **速率限制**: 使用 `--rate-limit` 参数控制请求频率,避免对目标造成过大压力
- **生产环境**: 在生产环境扫描前,请充分测试并评估潜在影响
- **误报**: 自动扫描工具可能存在误报,建议人工验证发现的漏洞

## 许可证

本项目采用 [MIT License](LICENSE) 开源协议。

## 贡献

欢迎提交 Issue 和 Pull Request!

1. Fork 本仓库
2. 创建你的特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交你的改动 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 开启一个 Pull Request

## 支持

- 提交 [Issue](https://github.com/bmslos/webjc-3.0/issues)
- 参与 [Discussions](https://github.com/bmslos/webjc-3.0/discussions)

## 更新日志

### v3.0 (2026-04-09)

- 新增13种漏洞检测器
- 异步并发架构支持
- 动态插件系统
- 自动登录和会话管理
- 多格式报告生成
- 代理支持

---

Made with ❤️ by bmslos
