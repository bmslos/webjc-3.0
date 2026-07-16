#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
漏洞检测器基类 - 统一检测器接口契约与公共逻辑

所有检测器应继承 BaseDetector 并实现 scan() 方法。
基类提供：
  - 统一的 __init__ 初始化（target/http/urls/forms/params/logger）
  - 统一的 _deduplicate_vulns 去重逻辑
  - 统一的 _build_vuln 漏洞字典构造
  - 统一的 _load_vuln_config 配置加载
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from core.config import VULN_CONFIG
from core.utils.logger import Logger


class BaseDetector(ABC):
    """漏洞检测器抽象基类"""

    # 子类可覆盖此属性作为检测器名称
    name: str = "BaseDetector"

    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 api_endpoints: Optional[List] = None, inputs: Optional[List] = None,
                 **kwargs):
        """
        初始化检测器公共属性

        Args:
            target: 扫描目标URL
            http: HTTP工具实例（HTTPUtils 或 AsyncHTTPUtils）
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
            api_endpoints: API端点列表
            inputs: 输入字段列表
        """
        self.target = target
        self.http = http
        self.urls = urls or [target]
        self.forms = forms or []
        self.params = params or []
        self.api_endpoints = api_endpoints or []
        self.inputs = inputs or []
        self.logger = Logger()

    @abstractmethod
    def scan(self) -> List[Dict]:
        """
        执行漏洞扫描

        子类必须实现此方法，返回发现的漏洞列表。

        Returns:
            漏洞字典列表
        """
        ...

    def _deduplicate_vulns(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        去重漏洞报告

        使用 (url, parameter, type) 作为去重键，
        保留每个唯一组合的第一条记录。

        Args:
            vulnerabilities: 原始漏洞列表

        Returns:
            去重后的漏洞列表
        """
        seen = set()
        unique_vulns = []

        for vuln in vulnerabilities:
            key = (
                vuln.get('url', ''),
                vuln.get('parameter', ''),
                vuln.get('type', '')
            )
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)

        return unique_vulns

    def _build_vuln(self, vuln_type: str, severity: str, url: str,
                    parameter: str = '', method: str = 'GET', payload: str = '',
                    description: str = '', recommendation: str = '',
                    **extra) -> Dict[str, Any]:
        """
        构造标准漏洞字典

        Args:
            vuln_type: 漏洞类型
            severity: 严重程度（严重/高危/中危/低危/信息）
            url: 漏洞URL
            parameter: 漏洞参数
            method: 请求方法
            payload: 使用的Payload
            description: 漏洞描述
            recommendation: 修复建议
            **extra: 额外字段

        Returns:
            标准化的漏洞字典
        """
        vuln = {
            'type': vuln_type,
            'severity': severity,
            'url': url,
            'parameter': parameter,
            'method': method,
            'payload': payload,
            'description': description,
            'recommendation': recommendation,
        }
        vuln.update(extra)
        return vuln

    def _load_vuln_config(self, config_key: str) -> Dict[str, Any]:
        """
        从 VULN_CONFIG 加载指定检测器的配置

        Args:
            config_key: VULN_CONFIG 中的键名（如 'sqli', 'xss'）

        Returns:
            配置字典
        """
        return VULN_CONFIG.get(config_key, {})
