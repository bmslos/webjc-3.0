#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS跨站脚本检测器 - 检测反射型和DOM型XSS漏洞
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.config import VULN_CONFIG
from core.utils.logger import Logger


class XSSDetector:
    """XSS跨站脚本检测器"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 **kwargs):
        """
        初始化XSS检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
        """
        self.name = "XSS跨站脚本"
        self.target = target
        self.http = http
        self.urls = urls or [target]
        self.forms = forms or []
        self.params = params or []
        self.logger = Logger()
        
        config = VULN_CONFIG.get('xss', {})
        self.payloads = config.get('payloads', [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg/onload=alert("XSS")>',
            '"><script>alert("XSS")</script>',
            "'> <script>alert('XSS')</script>",
            '<body onload=alert("XSS")>',
            '<iframe src="javascript:alert(\'XSS\')">',
            '<input onfocus=alert("XSS") autofocus>',
            '<marquee onstart=alert("XSS")>',
            '<video><source onerror="alert(\'XSS\')">',
            '<details open ontoggle=alert("XSS")>',
            '<select onfocus=alert("XSS")>',
            '"><img src=x onerror=alert("XSS")>',
            '<svg><script>alert("XSS")</script>',
        ])
    
    def scan(self) -> List[Dict]:
        """
        扫描XSS漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始XSS漏洞检测...")
        
        # 测试反射型XSS
        for url in self.urls[:50]:
            vulns = self._test_reflected_xss(url)
            vulnerabilities.extend(vulns)
            
            # 限制测试数量
            if len(vulnerabilities) > 15:
                break
        
        # 测试POST表单XSS
        for form in self.forms[:10]:
            vulns = self._test_post_xss(form)
            vulnerabilities.extend(vulns)
        
        # 测试DOM型XSS
        for url in self.urls[:30]:
            vulns = self._test_dom_xss(url)
            vulnerabilities.extend(vulns)
        
        return self._deduplicate_vulns(vulnerabilities)
    
    def _test_reflected_xss(self, url: str) -> List[Dict]:
        """测试反射型XSS"""
        vulnerabilities = []
        
        # 只对带参数的URL进行测试
        if '?' not in url:
            return vulnerabilities
        
        # 提取参数
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # 测试每个参数
        for param_name in query_params.keys():
            for payload in self.payloads[:10]:  # 限制payload数量
                # 构建测试URL
                test_params = query_params.copy()
                test_params[param_name] = [payload]
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment
                ))
                
                # 发送请求
                response = self.http.get(test_url)
                
                if response and response.status_code == 200:
                    # 检查payload是否被反射
                    if self._check_reflection(response.text, payload):
                        # 分析上下文
                        context = self._analyze_context(response.text, payload)
                        
                        vulnerabilities.append({
                            'type': 'XSS(反射型)',
                            'severity': '高危',
                            'url': test_url,
                            'parameter': param_name,
                            'method': 'GET',
                            'payload': payload,
                            'description': f'参数 {param_name} 存在XSS漏洞(反射型,上下文: {context}),用户输入被反射到页面且未正确编码',
                            'recommendation': '对用户输入进行HTML编码和上下文相关的输出编码。使用Content-Security-Policy头。实施输入验证和过滤。使用现代框架自动编码输出'
                        })
                        break  # 发现漏洞后停止测试当前参数
        
        return vulnerabilities
    
    def _test_post_xss(self, form: Dict) -> List[Dict]:
        """测试POST表单XSS"""
        vulnerabilities = []
        
        form_action = form.get('action', self.target)
        inputs = form.get('inputs', [])
        
        # 测试每个输入字段
        for input_field in inputs:
            input_name = input_field.get('name', '')
            input_type = input_field.get('type', 'text')
            
            # 跳过不可见字段
            if input_type in ['hidden', 'submit', 'button']:
                continue
            
            for payload in self.payloads[:5]:
                # 构建POST数据
                post_data = {input_name: payload}
                
                response = self.http.post(form_action, data=post_data)
                
                if response and response.status_code == 200:
                    if self._check_reflection(response.text, payload):
                        context = self._analyze_context(response.text, payload)
                        
                        vulnerabilities.append({
                            'type': 'XSS(反射型)',
                            'severity': '高危',
                            'url': form_action,
                            'parameter': input_name,
                            'method': 'POST',
                            'payload': payload,
                            'description': f'表单字段 {input_name} 存在XSS漏洞(POST反射型,上下文: {context})',
                            'recommendation': '对用户输入进行HTML编码。使用Content-Security-Policy头。实施输入验证。使用现代框架自动编码输出'
                        })
                        break
        
        return vulnerabilities
    
    def _test_dom_xss(self, url: str) -> List[Dict]:
        """测试DOM型XSS"""
        vulnerabilities = []
        
        response = self.http.get(url)
        if not response or response.status_code != 200:
            return vulnerabilities
        
        # 检查JavaScript中是否使用URL参数
        if self._check_dom_xss_pattern(response.text):
            # 检查是否有危险sink
            if '?' in url:
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                
                for param_name in query_params.keys():
                    vulnerabilities.append({
                        'type': 'XSS(DOM型)',
                        'severity': '高危',
                        'url': url,
                        'parameter': param_name,
                        'method': 'GET',
                        'payload': 'URL参数传递到JavaScript危险sink',
                        'description': f'参数 {param_name} 可能存在DOM型XSS,URL参数被传递到JavaScript危险函数',
                        'recommendation': '避免将URL参数直接传递给document.write()、innerHTML、eval()等危险sink。使用textContent代替innerHTML。实施Content-Security-Policy'
                    })
        
        return vulnerabilities
    
    def _check_reflection(self, html_content: str, payload: str) -> bool:
        """检查payload是否在响应中反射"""
        if not html_content:
            return False
        
        # 检查payload是否完整或部分反射
        payload_markers = [
            'alert("XSS")',
            "alert('XSS')",
            'onerror=alert',
            'onload=alert',
            '<script>',
            '<img src=x',
            '<svg',
        ]
        
        for marker in payload_markers:
            if marker in payload and marker in html_content:
                return True
        
        return False
    
    def _analyze_context(self, html_content: str, payload: str) -> str:
        """分析payload反射的上下文"""
        if not html_content:
            return '未知'
        
        # 查找payload位置
        payload_start = html_content.find('alert(')
        if payload_start == -1:
            payload_start = html_content.find('<script>')
        if payload_start == -1:
            payload_start = html_content.find('<svg')
        
        if payload_start == -1:
            return 'HTML内容'
        
        # 检查上下文
        context_start = max(0, payload_start - 100)
        context_end = min(len(html_content), payload_start + 100)
        context = html_content[context_start:context_end]
        
        if '<script>' in context or '</script>' in context:
            return 'JavaScript代码'
        elif 'onerror=' in context or 'onload=' in context or 'onclick=' in context:
            return '事件处理器'
        elif '<input' in context or '<textarea' in context:
            return 'HTML属性'
        else:
            return 'HTML内容'
    
    def _check_dom_xss_pattern(self, html_content: str) -> bool:
        """检查是否存在DOM型XSS模式"""
        # 检查是否使用location.search或URL参数
        dom_patterns = [
            r'location\.search',
            r'location\.hash',
            r'document\.URL',
            r'document\.documentURI',
            r'document\.referrer',
            r'window\.name',
            r'URLSearchParams',
        ]
        
        # 检查危险sink
        dangerous_sinks = [
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'\.insertAdjacentHTML\s*\(',
            r'eval\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'\.src\s*=',
        ]
        
        has_source = any(re.search(pattern, html_content) for pattern in dom_patterns)
        has_sink = any(re.search(pattern, html_content) for pattern in dangerous_sinks)
        
        return has_source and has_sink
    
    def _deduplicate_vulns(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """去重漏洞报告"""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            key = (vuln['url'], vuln.get('parameter', ''), vuln['type'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
