# -*- coding: utf-8 -*-
"""pytest 公共 fixtures"""

import sys
import os
import pytest

# 确保项目根目录在 sys.path 中
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def sample_vuln():
    """标准漏洞字典 fixture"""
    return {
        'type': 'SQL注入(错误回显)',
        'severity': '高危',
        'url': 'http://example.com/page?id=1',
        'parameter': 'id',
        'method': 'GET',
        'payload': "' OR '1'='1",
        'description': "参数 id 存在SQL注入漏洞",
        'recommendation': "使用参数化查询",
    }


@pytest.fixture
def sample_vulns_list():
    """多条漏洞列表 fixture（含重复项）"""
    return [
        {
            'type': 'SQL注入',
            'severity': '高危',
            'url': 'http://example.com/page?id=1',
            'parameter': 'id',
            'method': 'GET',
            'payload': "' OR '1'='1",
            'description': 'SQL注入漏洞',
            'recommendation': '使用参数化查询',
        },
        # 重复项（同URL同参数同类型）
        {
            'type': 'SQL注入',
            'severity': '高危',
            'url': 'http://example.com/page?id=1',
            'parameter': 'id',
            'method': 'GET',
            'payload': "UNION SELECT NULL",
            'description': '另一个SQL注入payload',
            'recommendation': '使用参数化查询',
        },
        # 不同URL（不应被去重）
        {
            'type': 'SQL注入',
            'severity': '高危',
            'url': 'http://example.com/other?id=1',
            'parameter': 'id',
            'method': 'GET',
            'payload': "' OR '1'='1",
            'description': '另一个页面的SQL注入',
            'recommendation': '使用参数化查询',
        },
        # 不同参数（不应被去重）
        {
            'type': 'SQL注入',
            'severity': '高危',
            'url': 'http://example.com/page?id=1',
            'parameter': 'name',
            'method': 'GET',
            'payload': "' OR '1'='1",
            'description': '不同参数的SQL注入',
            'recommendation': '使用参数化查询',
        },
    ]


@pytest.fixture
def xss_payloads():
    """XSS 测试 payload 列表"""
    return [
        '<script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        '<svg onload=alert(1)>',
        "';alert(String.fromCharCode(88,83,83))//",
    ]
