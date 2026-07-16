# Web Vulnerability Scanner Pro v3.1.1

[**English Version**](README_EN.md) | [**中文版本**](README.md)

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

一款功能强大的 Web 应用漏洞自动化扫描工具，支持 13 种漏洞检测类型，具备异步并发架构、动态插件系统、全局交叉去重引擎、二次验证机制、AI 误报过滤及多目标批量扫描等企业级特性。

## 核心特性

| 类别 | 功能 |
|------|------|
| **漏洞检测** | SQL 注入、XSS、CSRF、命令注入、SSRF、XXE、目录遍历、文件上传等 13 种 |
| **高性能架构** | 基于 aiohttp 的异步并发扫描，支持 50+ 协程并发 |
| **智能爬虫** | JavaScript 渲染、API 端点发现、表单自动识别 |
| **误报控制** | 三层去重（精确/输入点/根因）+ 二次验证 + AI 过滤 |
| **任务管理** | SQLite 持久化、多目标批量扫描、断点续传 |
| **报告输出** | HTML/JSON/CSV 多格式，XSS 安全防护 |
| **扩展性** | 动态插件系统，支持自定义检测器 |

## 支持的漏洞类型

| 漏洞类型 | 严重程度 | 检测方法 |
|----------|----------|----------|
| SQL 注入 | 高危 | 错误回显、布尔盲注、时间盲注、Union 注入 |
| XSS 跨站脚本 | 高危 | 反射型、DOM 型、上下文分析 |
| 命令注入 | 高危 | 系统命令注入、DNS 外带、时间延迟 |
| SSRF | 高危 | 内网访问、云元数据泄露 |
| XXE | 高危 | XML 外部实体注入、文件读取 |
| 目录遍历 | 高危 | 路径遍历、敏感文件读取 |
| 文件上传 | 高危 | 恶意文件上传、扩展名绕过、MIME 操纵 |
| CORS 错误配置 | 高危/中危 | Origin 反射、配置错误 |
| 敏感文件泄露 | 高危/中危 | .env、.git、配置文件公开访问 |
| 安全头缺失 | 高危/中危 | HSTS、CSP、X-Frame-Options 缺失 |
| CSRF | 中危 | Token 缺失、API 端点保护不足 |
| 弱密码 | 高危 | 常见用户名密码组合 |
| 开放重定向 | 中危 | URL 重定向到恶意站点 |

## 扫描流程

```
爬取 → 扫描 → 去重 → 验证 → AI过滤 → 报告
```

1. **爬取**：发现 URL、表单、参数、API 端点
2. **扫描**：13+ 检测器并发执行
3. **去重**：三层交叉去重消除重复报告
4. **验证**：可疑漏洞重新确认，计算置信度
5. **AI 过滤**：LLM 分析上下文，过滤明显误报（可选）
6. **报告**：HTML/JSON/CSV 多格式输出

## 快速开始

### 安装

```bash
git clone https://github.com/bmslos/webjc-3.0.git
cd webjc-3.0
pip install -r requirements.txt
python main.py --help
```

### 基础扫描

```bash
python main.py -t https://example.com
```

### 带认证扫描

```bash
python main.py -t https://example.com --cookie "session=abc123"
python main.py -t https://example.com --auth-token "your-token"
```

### 多目标批量扫描

```bash
python main.py -T targets.txt
```

### 启用 AI 分析

```bash
python main.py -t https://example.com --enable-ai --ai-api-key "sk-your-key"
```

### 任务管理

```bash
python main.py --list-tasks
python main.py --task-stats
python main.py --resume
```

## 命令行参数

| 参数 | 简写 | 说明 |
|------|------|------|
| `--target` | `-t` | 扫描目标 URL |
| `--targets` | `-T` | 多目标文件路径 |
| `--threads` | `-n` | 线程数（默认 10） |
| `--max-pages` | `-m` | 最大爬取页面数（默认 200） |
| `--rate-limit` | `-r` | 请求间隔（默认 0.1s） |
| `--cookie` | `-c` | 认证 Cookie |
| `--auth-token` | - | Bearer Token |
| `--proxy` | - | HTTP 代理地址 |
| `--enable-ai` | - | 启用 AI 分析 |
| `--no-dedup` | - | 禁用去重 |
| `--no-verify` | - | 禁用二次验证 |
| `--no-crawler` | - | 禁用爬虫 |
| `--report-format` | `-f` | 报告格式（html/json/csv） |
| `--verbose` | `-v` | 详细输出 |
| `--list-plugins` | - | 列出可用插件 |

## 项目结构

```
webjc-3.0/
├── main.py              # 主入口
├── requirements.txt     # 依赖列表
├── LICENSE              # MIT 许可证
├── core/                # 核心模块
│   ├── scanner.py       # 扫描引擎
│   ├── crawler.py       # 网站爬虫
│   ├── dedup_engine.py  # 全局去重引擎
│   ├── verification.py  # 二次验证
│   ├── task_manager.py  # 任务管理
│   ├── ai_analyzer.py   # AI 分析引擎
│   ├── plugin_manager.py # 插件管理器
│   ├── config.py        # 配置文件
│   ├── detectors/       # 漏洞检测器（13种）
│   │   ├── base.py      # 检测器基类
│   │   └── ...
│   └── utils/           # 工具模块
│       ├── http.py      # HTTP 客户端
│       ├── logger.py    # 日志记录器
│       └── report.py    # 报告生成器
├── plugins/             # 用户插件目录
├── tests/               # 单元测试（26个）
└── pytest.ini           # pytest 配置
```

## 版本更新

### v3.1.1（2026-07-16）

**安全修复**
- 修复 HTML 报告存储型 XSS（Jinja2 autoescape）
- 恢复异步 HTTP SSL 证书验证
- 升级存在 CVE 的依赖
- LLM 提示词注入防御
- 收紧插件加载白名单

**架构优化**
- 提取 `BaseDetector(ABC)` 基类，消除 ~600 行重复代码
- 修复 Logger 单例崩溃问题
- 修复异步函数内同步 HTTP 阻塞
- 删除死代码 `session_manager.py`

**质量提升**
- 新增 26 个单元测试
- 修复 3 处静默吞异常
- 报告生成器改用 Jinja2 模板
- HTTP 工具添加上下文管理器

**性能优化**
- LLM 分析结果缓存
- TaskManager 批量插入
- 爬虫队列改用 `deque`（O(1)）
- 限速器线程安全

### v3.1（2026-05-14）

- 全局交叉去重引擎
- 二次验证与上下文理解
- 多目标批量扫描与任务持久化
- AI 分析引擎（支持 OpenAI/DeepSeek/通义千问）
- 任务管理命令（`--list-tasks`、`--task-stats`、`--resume`）

### v3.0（2026-04-09）

- 13 种漏洞检测器
- 异步并发架构
- 动态插件系统
- 自动登录支持
- 多格式报告

## 插件开发

继承 `BaseDetector` 基类即可快速创建自定义检测器：

```python
from core.detectors.base import BaseDetector

class MyDetector(BaseDetector):
    def scan(self):
        vulnerabilities = []
        for url in self.urls:
            response = self.http.get(url)
            if self._check_vuln(response):
                vulnerabilities.append(self._build_vuln(
                    vuln_type='漏洞类型',
                    severity='高危',
                    url=url,
                    parameter='参数名',
                    payload='payload',
                    description='描述',
                    recommendation='修复建议'
                ))
        return self._deduplicate_vulns(vulnerabilities)
```

## 注意事项

- **合法使用**：仅扫描授权目标，未经授权扫描可能违法
- **速率限制**：使用 `--rate-limit` 控制请求频率
- **误报**：自动扫描可能存在误报，建议人工验证
- **AI 功能**：未配置 API Key 时自动降级为规则引擎

## 许可证

[MIT License](LICENSE)

## 贡献

欢迎提交 Issue 和 Pull Request！

---

Made with ❤️ by bmslos