# Web漏洞扫描工具增强版 - 快速使用指南

## 项目简介

Web漏洞扫描工具增强版(webjc-pro)是一个专业的Web应用安全扫描框架，相比原版(webjc)实现了：

- ✅ **异步并发架构** - 性能提升10-50倍
- ✅ **JavaScript渲染** - 支持SPA/动态页面爬取
- ✅ **动态插件系统** - 可扩展的检测器
- ✅ **自动登录认证** - 支持复杂认证场景
- ✅ **会话智能管理** - Token自动刷新
- ✅ **全面漏洞覆盖** - 13+种漏洞类型

## 快速安装

### 1. 安装依赖

```bash
cd webjc-pro
pip install -r requirements.txt
```

### 2. (可选) 安装Playwright支持JS渲染

```bash
playwright install chromium
```

## 使用示例

### 基础扫描

```bash
# 最简单的用法(异步模式)
python main.py -t http://example.com

# 指定报告格式和输出目录
python main.py -t http://example.com -f json -o ./reports
```

### 认证扫描

```bash
# 使用Cookie认证
python main.py -t http://example.com -c "session=abc123;user=admin"

# 使用Bearer Token
python main.py -t http://example.com --auth-token "your-jwt-token"

# 自动登录
python main.py -t http://example.com \
  --auto-login \
  --login-url http://example.com/login \
  --username admin \
  --password 123456
```

### 高级用法

```bash
# 使用代理(配合Burp Suite)
python main.py -t http://example.com --proxy http://127.0.0.1:8080

# 自定义并发和爬取参数
python main.py -t http://example.com \
  --threads 20 \
  --max-pages 500 \
  --rate-limit 0.05

# 禁用爬虫,仅扫描指定URL
python main.py -t http://example.com/api/endpoint --no-crawler

# 同步模式(兼容旧环境)
python main.py -t http://example.com --sync
```

### 插件使用

```bash
# 列出所有可用插件
python main.py -t http://example.com --list-plugins

# 使用自定义插件目录
python main.py -t http://example.com --plugin-dir ./my-plugins
```

## 命令行参数详解

| 参数 | 简写 | 说明 | 默认值 |
|-----|------|------|--------|
| --target | -t | 扫描目标URL(必需) | - |
| --timeout | -T | HTTP请求超时(秒) | 15 |
| --threads | -n | 扫描线程数 | 10 |
| --max-pages | -m | 爬虫最大页面数 | 200 |
| --rate-limit | -r | 请求间隔(秒) | 0.1 |
| --cookie | -c | 认证Cookie字符串 | - |
| --header | -H | 自定义请求头(可多次使用) | - |
| --auth-token | - | Bearer Token | - |
| --auto-login | - | 启用自动登录 | False |
| --login-url | - | 登录页面URL | - |
| --username | -u | 登录用户名 | - |
| --password | -p | 登录密码 | - |
| --proxy | - | HTTP代理地址 | - |
| --no-crawler | - | 禁用爬虫 | False |
| --sync | - | 使用同步模式 | False |
| --plugin-dir | - | 插件目录 | plugins/ |
| --list-plugins | - | 列出插件 | False |
| --output | -o | 报告输出目录 | reports |
| --report-format | -f | 报告格式(html/json/csv) | html |
| --verbose | -v | 详细输出 | False |
| --quiet | -q | 静默模式 | False |

## 开发自定义插件

### 1. 创建插件文件

在 `plugins/` 目录下创建Python文件,例如 `my_detector.py`:

```python
from typing import Dict, List, Optional
from core.utils.logger import Logger


class MyCustomDetector:
    """自定义检测器示例"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, **kwargs):
        self.name = "我的自定义检测"
        self.target = target
        self.http = http
        self.urls = urls or [target]
        self.forms = forms or []
        self.logger = Logger()
    
    def scan(self) -> List[Dict]:
        """执行检测"""
        vulnerabilities = []
        
        self.logger.info("开始自定义检测...")
        
        for url in self.urls:
            # 你的检测逻辑
            if self._check_vulnerability(url):
                vulnerabilities.append({
                    'type': '自定义漏洞类型',
                    'severity': '高危',
                    'url': url,
                    'parameter': 'test_param',
                    'method': 'GET',
                    'payload': 'test_payload',
                    'description': '发现自定义漏洞',
                    'recommendation': '修复建议...'
                })
        
        return vulnerabilities
    
    def _check_vulnerability(self, url: str) -> bool:
        """检测逻辑"""
        response = self.http.get(url)
        if response:
            # 检查漏洞特征
            return 'vulnerable' in response.text
        return False
```

### 2. 自动加载

扫描器会自动发现并加载 `plugins/` 目录中的所有检测器!

```bash
python main.py -t http://example.com
```

## 报告格式

### HTML报告
美观的现代化UI报告,包含漏洞详情、修复建议和统计信息。

### JSON报告
结构化数据,便于程序处理和集成。

```json
{
  "target": "http://example.com",
  "scan_time": "2024-01-01 12:00:00",
  "vulnerabilities": [
    {
      "type": "SQL注入",
      "severity": "高危",
      "url": "http://example.com/page?id=1",
      "parameter": "id",
      "method": "GET",
      "payload": "' OR 1=1 --",
      "description": "...",
      "recommendation": "..."
    }
  ],
  "scan_stats": {
    "urls_discovered": 50,
    "forms_discovered": 10,
    "params_discovered": 25
  }
}
```

### CSV报告
表格格式,适合导入Excel或其他工具。

## 最佳实践

### 1. 性能调优

```bash
# 快速扫描(小站点)
python main.py -t http://small-site.com -n 5 -m 50

# 大规模扫描(大型站点)
python main.py -t http://large-site.com -n 20 -m 500 -r 0.05
```

### 2. 降低误报

```bash
# 使用较慢的请求间隔,提高准确性
python main.py -t http://example.com -r 0.5
```

### 3. 配合Burp Suite

```bash
# 发送流量到Burp进行人工验证
python main.py -t http://example.com --proxy http://127.0.0.1:8080
```

### 4. 持续集成

```bash
# CI/CD中使用,仅输出报告路径
python main.py -t http://example.com -q -f json
```

## 常见问题

### Q: 异步 vs 同步模式?

**A:** 默认使用异步模式(性能更好)。如果遇到问题,可用 `--sync` 切换到同步模式。

### Q: Playwright安装失败?

**A:** Playwright是可选的。不安装时会自动回退到静态爬取模式。

```bash
# 国内网络可尝试镜像
PLAYWRIGHT_DOWNLOAD_HOST=https://npmmirror.com/mirrors/playwright/ playwright install chromium
```

### Q: 如何降低误报率?

**A:** 
1. 增加 `--rate-limit` 避免被限流
2. 使用 `--verbose` 查看详细日志
3. 手动验证高危漏洞

### Q: 支持哪些认证方式?

**A:** 
- Cookie认证
- Bearer Token
- 表单自动登录
- OAuth2客户端凭证
- 自定义认证(通过插件)

## 与原版的区别

详见 [COMPARISON.md](COMPARISON.md)

## 许可证

本项目仅供学习和合法安全测试使用。请遵守当地法律法规。

## 贡献

欢迎提交Issue和Pull Request!

## 支持

- 问题反馈: 提交Issue
- 使用讨论: 查看Wiki
- 文档: 阅读源码和注释
