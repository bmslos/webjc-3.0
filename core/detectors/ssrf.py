#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSRF服务端请求伪造检测器 - 检测可访问内部网络资源的漏洞
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.config import VULN_CONFIG
from core.utils.logger import Logger


class SSRFDetector:
    """SSRF服务端请求伪造检测器"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 api_endpoints: Optional[List] = None, **kwargs):
        """
        初始化SSRF检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
            api_endpoints: API端点列表
        """
        self.name = "SSRF(服务端请求伪造)"
        self.target = target
        self.http = http
        self.urls = urls or [target]
        self.forms = forms or []
        self.params = params or []
        self.api_endpoints = api_endpoints or []
        self.logger = Logger()
        
        config = VULN_CONFIG.get('ssrf', {})
        self.payloads = config.get('payloads', [
            'http://127.0.0.1',
            'http://localhost',
            'http://169.254.169.254/latest/meta-data/',
            'file:///etc/passwd',
        ])
        
        # 云元数据特征
        self.metadata_patterns = [
            r'ami-id',
            r'instance-id',
            r'local-ipv4',
            r'public-ipv4',
            r'identity-credentials',
            r'iam/security-credentials',
            r'hostname',
            r'instance-type',
        ]
    
    def scan(self) -> List[Dict]:
        """
        扫描SSRF漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始SSRF漏洞检测...")
        
        # 测试GET参数
        for url in self.urls[:50]:
            vulns = self._test_url_params(url)
            vulnerabilities.extend(vulns)
            
            if len(vulnerabilities) > 10:
                break
        
        # 测试API端点
        for endpoint in self.api_endpoints[:20]:
            endpoint_url = endpoint.get('url', '')
            if endpoint_url:
                vulns = self._test_api_endpoint(endpoint_url)
                vulnerabilities.extend(vulns)
        
        # 测试POST表单
        for form in self.forms[:10]:
            if form.get('method', 'GET').upper() == 'POST':
                vulns = self._test_post_ssrf(form)
                vulnerabilities.extend(vulns)
        
        return self._deduplicate_vulns(vulnerabilities)
    
    def _test_url_params(self, url: str) -> List[Dict]:
        """测试URL参数的SSRF"""
        vulnerabilities = []
        
        if '?' not in url:
            return vulnerabilities
        
        # 提取参数
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # 重点测试URL相关参数
        url_params = ['url', 'link', 'redirect', 'fetch', 'image', 'proxy', 'api', 'src', 'source', 'file', 'path']
        target_params = [p for p in query_params.keys() if p.lower() in url_params]
        
        if not target_params:
            target_params = list(query_params.keys())[:5]
        
        for param_name in target_params:
            for payload in self.payloads[:6]:  # 限制payload数量
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
                
                response = self.http.get(test_url)
                
                if response and response.status_code == 200:
                    if self._check_ssrf_response(response.text, payload):
                        vulnerabilities.append({
                            'type': 'SSRF(服务端请求伪造)',
                            'severity': '高危',
                            'url': test_url,
                            'parameter': param_name,
                            'method': 'GET',
                            'payload': payload,
                            'description': f'参数 {param_name} 存在SSRF漏洞,可访问内部网络资源或云服务元数据',
                            'recommendation': '对用户提供的URL进行严格验证。使用URL白名单。禁止访问内网IP段(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16)。使用网络隔离'
                        })
                        break  # 发现漏洞后停止测试当前参数
        
        return vulnerabilities
    
    def _test_api_endpoint(self, url: str) -> List[Dict]:
        """测试API端点的SSRF"""
        vulnerabilities = []
        
        # 测试常见的SSRF payload
        test_payloads = [
            'http://127.0.0.1',
            'http://169.254.169.254/latest/meta-data/',
        ]
        
        for payload in test_payloads:
            response = self.http.post(url, json={'url': payload})
            
            if response and response.status_code == 200:
                if self._check_ssrf_response(response.text, payload):
                    vulnerabilities.append({
                        'type': 'SSRF(服务端请求伪造)',
                        'severity': '高危',
                        'url': url,
                        'parameter': 'POST Body',
                        'method': 'POST',
                        'payload': payload,
                        'description': f'API端点 {url} 存在SSRF漏洞',
                        'recommendation': '验证用户提供的URL。使用白名单机制。禁止访问内网地址'
                    })
                    break
        
        return vulnerabilities
    
    def _test_post_ssrf(self, form: Dict) -> List[Dict]:
        """测试POST表单的SSRF"""
        vulnerabilities = []
        
        form_action = form.get('action', self.target)
        inputs = form.get('inputs', [])
        
        # 查找URL相关输入字段
        url_inputs = []
        for input_field in inputs:
            input_name = input_field.get('name', '').lower()
            if any(keyword in input_name for keyword in ['url', 'link', 'image', 'file', 'source']):
                url_inputs.append(input_field.get('name'))
        
        # 测试每个URL输入字段
        for input_name in url_inputs:
            for payload in self.payloads[:4]:
                post_data = {input_name: payload}
                response = self.http.post(form_action, data=post_data)
                
                if response and response.status_code == 200:
                    if self._check_ssrf_response(response.text, payload):
                        vulnerabilities.append({
                            'type': 'SSRF(服务端请求伪造)',
                            'severity': '高危',
                            'url': form_action,
                            'parameter': input_name,
                            'method': 'POST',
                            'payload': payload,
                            'description': f'表单字段 {input_name} 存在SSRF漏洞',
                            'recommendation': '验证用户提供的URL。使用白名单机制。禁止访问内网地址'
                        })
                        break
        
        return vulnerabilities
    
    def _check_ssrf_response(self, response_text: str, payload: str) -> bool:
        """检查响应是否包含SSRF成功利用的特征"""
        if not response_text:
            return False
        
        # 检查云元数据特征
        for pattern in self.metadata_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # 检查本地文件内容
        if 'file:///etc/passwd' in payload:
            if re.search(r'root:x:', response_text, re.IGNORECASE):
                return True
        
        # 检查localhost响应特征
        if '127.0.0.1' in payload or 'localhost' in payload:
            # 如果响应包含典型的本地服务响应
            local_indicators = [
                r'Apache.*Server',
                r'nginx',
                r'IIS',
                r'Tomcat',
                r'localhost',
            ]
            for indicator in local_indicators:
                if re.search(indicator, response_text, re.IGNORECASE):
                    return True
        
        return False
    
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
