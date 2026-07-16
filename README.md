# Web Vulnerability Scanner Pro v3.1

[**English Version**](README_EN.md) | [**中文版本**](README.md)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

一款功能强大的Web应用漏洞自动化扫描工具，支持13种漏洞检测类型，具备异步并发架构、动态插件系统、全局交叉去重引擎、二次验证机制、AI误报过滤及多目标批量扫描等企业级特性。

## 特性

- **13种漏洞检测**: 涵盖SQL注入、XSS、CSRF、命令注入、SSRF、XXE等常见Web漏洞
- **异步并发架构**: 基于aiohttp的高性能异步扫描，支持50+并发协程
- **智能网站爬虫**: 支持JavaScript渲染、API端点发现、表单自动识别
- **动态插件系统**: 支持自定义检测器插件，灵活扩展检测能力
- **自动登录支持**: 支持Cookie认证、Bearer Token、表单自动登录、OAuth2
- **全局交叉去重引擎**: 三层去重（精确/输入点/根因），有效消除跨检测器重复报告
- **二次验证机制**: 发现可疑漏洞后使用不同payload重新确认，降低误报率
- **AI误报过滤**: 集成大语言模型分析漏洞上下文，自动识别明显误报（可选）
- **智能payload生成**: 根据参数类型和上下文动态生成针对性测试用例（可选）
- **多目标批量扫描**: 支持从文件加载多个目标URL，自动创建任务队列
- **任务持久化**: 基于SQLite存储扫描任务和漏洞数据，支持断点续传
- **多格式报告**: 自动生成HTML、JSON、CSV格式的扫描报告
- **代理支持**: 兼容HTTP/SOCKS代理，可与Burp Suite等工具配合使用

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

## 架构演进

### v3.0 基础架构
- 异步并发爬虫 + 13个检测器 + 插件系统 + 自动登录

### v3.1 企业级增强
| 模块 | 功能 | 说明 |
|------|------|------|
| `dedup_engine.py` | 全局交叉去重 | 三层去重（L1精确/L2输入点/L3根因合并），消除跨检测器重复报告 |
| `verification.py` | 二次验证+上下文理解 | 7种参数类型推断，SQL/XSS/命令注入/目录遍历独立验证策略 |
| `task_manager.py` | 多目标+任务持久化 | SQLite数据库，批量扫描、任务状态跟踪、断点续传、历史查询 |
| `ai_analyzer.py` | AI分析引擎 | LLM误报过滤、智能payload生成、修复建议增强（兼容OpenAI/DeepSeek/通义千问） |

### v3.1.1 安全加固与质量优化

对 v3.1 进行了全面的代码审计和四阶段改进，共 22 项优化：

**安全修复（高危）**
- 修复 HTML 报告存储型 XSS（改用 Jinja2 autoescape 自动转义）
- 恢复异步 HTTP SSL 证书验证（原 `ssl=False` 全局禁用）
- 升级存在已知 CVE 的依赖（requests/aiohttp/Jinja2/urllib3）
- 防御 LLM 提示词注入（字段截断 + 防御指令 + 数据分隔符隔离）
- 收紧插件加载白名单（仅接受 Detector/Scanner 后缀类）

**架构优化**
- 提取 `BaseDetector(ABC)` 抽象基类，统一 13 个检测器的 `__init__`/`_deduplicate_vulns`/`_build_vuln`，消除约 600 行重复代码
- 修复 Logger 单例 `__new__` 签名崩溃，新增 `set_verbose()` 运行时切换日志级别
- 修复异步函数内同步 HTTP 调用阻塞事件循环（新增 `_async_get()` 兼容方法）
- 删除死代码 `session_manager.py`（从未被引用）
- 补充 `__init__.py` 包文件，规范化包结构

**质量提升**
- 新增 26 个单元测试（BaseDetector/Logger/XSS转义），配置 pytest.ini 和 conftest.py
- 修复 3 处静默吞异常（`except Exception: pass` → 带日志记录）
- main.py 中 5 处 print 改为 logging
- 用 Jinja2 模板重写报告生成器，将 285 行 f-string 拼接拆分为模板渲染
- HTTP 工具添加上下文管理器（`__enter__/__exit__` + `__aenter__/__aexit__`）

**性能优化**
- LLM 分析结果缓存（避免对相同漏洞重复调用）
- TaskManager 逐条 INSERT 改为 `executemany` 批量插入
- 爬虫 URL 队列改用 `deque(maxlen=2000)`，`pop(0)` 改为 `popleft()`（O(1)）
- 限速器添加 `threading.Lock`/`asyncio.Lock` 保证线程/协程安全
- 检测器中多次访问的 `response.text` 缓存到局部变量

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

# 安装AI分析依赖（可选，启用AI功能时需要）
pip install openai

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

### 多目标批量扫描

```bash
# 从文件加载目标URL（每行一个URL）
python main.py -T targets.txt

# targets.txt 示例：
# https://site1.com
# https://site2.com
# https://site3.com
```

### 启用AI分析

```bash
# 使用OpenAI GPT-4
python main.py -t https://example.com \
  --enable-ai \
  --ai-api-key "sk-your-key"

# 使用环境变量（推荐）
export LLM_API_KEY="sk-your-key"
python main.py -t https://example.com --enable-ai

# 使用DeepSeek模型
python main.py -t https://example.com \
  --enable-ai \
  --ai-api-base "https://api.deepseek.com/v1" \
  --ai-model "deepseek-chat"

# 使用通义千问
python main.py -t https://example.com \
  --enable-ai \
  --ai-api-base "https://dashscope.aliyuncs.com/compatible-mode/v1" \
  --ai-model "qwen-turbo"
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

# 禁用去重和验证（快速扫描模式）
python main.py -t https://example.com --no-dedup --no-verify

# 生成JSON格式报告
python main.py -t https://example.com --report-format json

# 详细输出模式
python main.py -t https://example.com --verbose
```

### 任务管理

```bash
# 查看所有扫描任务
python main.py --list-tasks

# 查看任务统计信息
python main.py --task-stats

# 恢复中断的扫描任务
python main.py --resume
```

## 命令行参数

### 目标参数

| 参数 | 简写 | 说明 |
|-----|------|------|
| `--target` | `-t` | 扫描目标URL（单目标） |
| `--targets` | `-T` | 扫描目标文件路径（多目标，每行一个URL） |

### 扫描配置

| 参数 | 简写 | 默认值 | 说明 |
|-----|------|--------|------|
| `--timeout` | - | 15 | HTTP请求超时时间(秒) |
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
| `--no-dedup` | 禁用全局交叉去重 |
| `--no-verify` | 禁用二次验证 |
| `--enable-ai` | 启用AI分析(误报过滤+智能payload) |
| `--ai-api-key` | LLM API密钥 |
| `--ai-api-base` | LLM API基础URL |
| `--ai-model` | LLM模型名称(默认gpt-4o-mini) |
| `--plugin-dir` | 插件目录路径 |
| `--list-plugins` | 列出所有可用插件 |

### 任务管理

| 参数 | 说明 |
|-----|------|
| `--list-tasks` | 列出所有扫描任务 |
| `--task-stats` | 显示任务统计信息 |
| `--resume` | 恢复中断的扫描任务 |

### 输出配置

| 参数 | 简写 | 默认值 | 说明 |
|-----|------|--------|------|
| `--output` | `-o` | reports | 报告输出目录 |
| `--report-format` | `-f` | html | 报告格式(html/json/csv) |
| `--verbose` | `-v` | - | 详细输出模式 |
| `--quiet` | `-q` | - | 静默模式,仅输出报告路径 |

## 扫描流水线

扫描过程按以下顺序执行：

```
1. 网站爬取          → 发现URL、表单、参数、API端点
2. 漏洞扫描          → 13+检测器并发执行
3. 全局交叉去重      → 三层去重（精确/输入点/根因合并）
4. 二次验证          → 可疑漏洞重新确认，计算置信度
5. AI误报过滤        → LLM分析上下文，过滤明显误报（可选）
6. 报告生成          → HTML/JSON/CSV多格式输出
```

## 项目结构

```
webjc-3.0/
├── main.py                      # 主入口文件
├── requirements.txt             # Python依赖
├── README.md                    # 项目说明(中文)
├── README_EN.md                 # Project Documentation(English)
├── LICENSE                      # MIT许可证
├── .gitignore                   # Git忽略配置
│
├── core/                        # 核心模块
│   ├── config.py                # 配置文件
│   ├── scanner.py               # 扫描引擎(集成去重/验证/AI流水线)
│   ├── crawler.py               # 网站爬虫
│   ├── plugin_manager.py        # 插件管理器
│   ├── dedup_engine.py          # 全局交叉去重引擎(v3.1新增)
│   ├── verification.py          # 二次验证与上下文理解(v3.1新增)
│   ├── task_manager.py          # 多目标任务管理器(v3.1新增)
│   ├── ai_analyzer.py           # AI分析引擎(v3.1新增)
│   │
│   ├── detectors/               # 漏洞检测器
│   │   ├── __init__.py          # 包初始化
│   │   ├── base.py              # 检测器抽象基类(v3.1.1新增)
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
│       ├── __init__.py          # 包初始化
│       ├── http.py              # HTTP客户端(同步/异步)
│       ├── logger.py            # 日志记录器
│       └── report.py            # 报告生成器
│
├── data/                        # 数据存储(v3.1新增)
│   └── scan_tasks.db            # SQLite任务数据库
│
├── plugins/                     # 用户插件目录
│   ├── __init__.py              # 包初始化
│   └── xxe_detector.py          # XXE检测器示例插件(薄封装,复用内置检测器)
│
├── pytest.ini                   # pytest配置(v3.1.1新增)
│
└── tests/                       # 单元测试
    ├── __init__.py              # 包初始化
    ├── conftest.py              # pytest公共fixtures(v3.1.1新增)
    ├── test_new_modules.py      # v3.1新增模块测试
    ├── test_base_detector.py    # BaseDetector单元测试(v3.1.1新增)
    ├── test_logger.py           # Logger单元测试(v3.1.1新增)
    └── test_report.py           # 报告XSS转义测试(v3.1.1新增)
```

## 自定义插件开发

### 创建插件

在 `plugins/` 目录下创建Python文件,实现检测器类:

```python
# plugins/my_detector.py
from typing import Dict, List
from core.detectors.base import BaseDetector


class MyDetector(BaseDetector):
    """自定义检测器示例"""

    def __init__(self, target: str, http, urls=None, forms=None, **kwargs):
        super().__init__(target, http, urls=urls, forms=forms, **kwargs)
        self.name = "我的检测器"

    def scan(self) -> List[Dict]:
        """执行扫描,返回漏洞列表（基类自动提供去重和漏洞构造方法）"""
        vulnerabilities = []

        # 你的检测逻辑
        for url in self.urls:
            response = self.http.get(url)
            if self._check_vulnerability(response):
                # 使用基类的 _build_vuln 构造标准漏洞字典
                vulnerabilities.append(self._build_vuln(
                    vuln_type='漏洞类型',
                    severity='高危',  # 严重/高危/中危/低危/信息
                    url=url,
                    parameter='参数名',
                    payload='使用的payload',
                    description='漏洞描述',
                    recommendation='修复建议'
                ))

        # 基类的 _deduplicate_vulns 自动去重
        return self._deduplicate_vulns(vulnerabilities)

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
# 运行所有单元测试
pytest

# 运行特定测试文件
pytest tests/test_base_detector.py -v
```

### 添加新的检测器

1. 在 `core/detectors/` 下创建新文件
2. 继承 `BaseDetector` 基类，实现 `scan()` 方法（自动获得去重和漏洞构造能力）
3. 在 `core/config.py` 的 `VULN_CONFIG` 中添加配置
4. 在 `core/scanner.py` 的 `detector_mapping` 中注册

参考 `core/detectors/base.py` 了解基类接口，`core/detectors/sqli.py` 作为完整示例。

## 注意事项

- **合法使用**: 仅对你拥有授权的目标进行扫描,未经授权扫描他人网站可能违法
- **速率限制**: 使用 `--rate-limit` 参数控制请求频率,避免对目标造成过大压力
- **生产环境**: 在生产环境扫描前,请充分测试并评估潜在影响
- **误报**: 自动扫描工具可能存在误报,建议人工验证发现的漏洞
- **AI功能**: AI分析为可选功能,未配置API Key时自动降级为规则引擎,不影响基础扫描

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

### v3.1.1 (2026-07-16)

**安全加固与质量优化（22 项改进）**

安全修复：
- 修复 HTML 报告存储型 XSS（改用 Jinja2 autoescape 自动转义）
- 恢复异步 HTTP SSL 证书验证（原 `ssl=False` 全局禁用）
- 升级存在已知 CVE 的依赖（requests/aiohttp/Jinja2/urllib3）
- 防御 LLM 提示词注入（字段截断 + 防御指令 + 数据分隔符隔离）
- 收紧插件加载白名单（仅接受 Detector/Scanner 后缀类）

架构优化：
- 提取 `BaseDetector(ABC)` 抽象基类，消除 13 个检测器中约 600 行重复代码
- 修复 Logger 单例 `__new__` 签名崩溃，新增 `set_verbose()` 方法
- 修复异步函数内同步 HTTP 调用阻塞事件循环
- 删除死代码 `session_manager.py`，移除冗余依赖 `asyncio-mqtt`
- 补充 `__init__.py` 包文件，规范化包结构

质量提升：
- 新增 26 个单元测试，配置 pytest.ini 和 conftest.py
- 修复 3 处静默吞异常，main.py 5 处 print 改为 logging
- 用 Jinja2 模板重写报告生成器，拆分 285 行长函数
- HTTP 工具添加上下文管理器（`__enter__/__exit__` + `__aenter__/__aexit__`）

性能优化：
- LLM 分析结果缓存，避免重复调用
- TaskManager 批量 INSERT（`executemany`）
- 爬虫 URL 队列改用 `deque(maxlen=2000)`，`pop(0)` 改为 `popleft()`（O(1)）
- 限速器添加线程/协程安全锁

### v3.1 (2026-05-14)

**企业级增强**
- 新增全局交叉去重引擎（三层去重：精确/输入点/根因合并）
- 新增二次验证模块（参数类型推断、多策略验证、置信度评分）
- 新增多目标批量扫描和任务持久化（SQLite数据库、断点续传）
- 新增AI分析引擎（LLM误报过滤、智能payload生成、修复建议增强）
- 新增任务管理命令（`--list-tasks`、`--task-stats`、`--resume`）
- 更新扫描引擎，集成去重/验证/AI后处理流水线
- 更新主入口，支持多目标文件和AI配置参数

### v3.0 (2026-04-09)

- 新增13种漏洞检测器
- 异步并发架构支持
- 动态插件系统
- 自动登录和会话管理
- 多格式报告生成
- 代理支持

---

Made with ❤️ by bmslos
