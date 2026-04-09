#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CSRF跨站请求伪造检测器 - 检测表单和API端点是否缺少CSRF保护
"""

from typing import Dict, List, Optional
from core.config import VULN_CONFIG
from core.utils.logger import Logger


class CSRFDetector:
    """CSRF跨站请求伪造检测器"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 api_endpoints: Optional[List] = None, **kwargs):
        """
        初始化CSRF检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
            api_endpoints: API端点列表
        """
        self.name = "CSRF(跨站请求伪造)"
        self.target = target
        self.http = http
        self.urls = urls or [target]
        self.forms = forms or []
        self.params = params or []
        self.api_endpoints = api_endpoints or []
        self.logger = Logger()
        
        config = VULN_CONFIG.get('csrf', {})
        self.token_patterns = config.get('token_patterns', [
            'csrf', 'token', '_token', 'authenticity_token',
            'csrfmiddlewaretoken', 'xsrf', '_xsrf', 'csrf_token'
        ])
    
    def scan(self) -> List[Dict]:
        """
        扫描CSRF漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始CSRF漏洞检测...")
        
        # 测试所有POST表单
        for form in self.forms:
            if form.get('method', 'GET').upper() == 'POST':
                vulns = self._test_form_csrf(form)
                vulnerabilities.extend(vulns)
        
        # 测试API端点
        for endpoint in self.api_endpoints[:20]:
            method = endpoint.get('method', 'GET').upper()
            if method in ['POST', 'PUT', 'DELETE', 'PATCH']:
                vulns = self._test_api_csrf(endpoint)
                vulnerabilities.extend(vulns)
        
        return self._deduplicate_vulns(vulnerabilities)
    
    def _test_form_csrf(self, form: Dict) -> List[Dict]:
        """测试表单是否缺少CSRF保护"""
        vulnerabilities = []
        
        form_action = form.get('action', self.target)
        inputs = form.get('inputs', [])
        
        # 检查是否存在CSRF token隐藏字段
        has_csrf_token = False
        for input_field in inputs:
            input_name = input_field.get('name', '').lower()
            if any(pattern in input_name for pattern in self.token_patterns):
                has_csrf_token = True
                break
        
        # 如果没有CSRF token,报告漏洞
        if not has_csrf_token:
            vulnerabilities.append({
                'type': 'CSRF(跨站请求伪造)',
                'severity': '中危',
                'url': form_action,
                'parameter': 'N/A',
                'method': 'POST',
                'payload': '缺少CSRF Token',
                'description': f'表单 {form_action} 缺少CSRF保护,攻击者可以伪造用户请求执行未授权操作',
                'recommendation': '为所有状态修改操作添加CSRF token验证。在表单中添加隐藏的CSRF token字段。使用SameSite Cookie属性。验证Referer/Origin头'
            })
        
        return vulnerabilities
    
    def _test_api_csrf(self, endpoint: Dict) -> List[Dict]:
        """测试API端点是否要求CSRF保护"""
        vulnerabilities = []
        
        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET').upper()
        
        # 发送不带自定义头的请求
        response = self.http.post(url, data={'test': '1'})
        
        if response:
            # 如果成功执行(200),说明可能缺少CSRF保护
            if response.status_code == 200:
                # 检查响应是否包含成功标识
                response_headers = {k.lower(): v for k, v in response.headers.items()}
                
                # 检查是否要求CSRF相关头
                if 'x-csrf-token' not in response_headers and 'x-requested-with' not in response_headers:
                    vulnerabilities.append({
                        'type': 'CSRF(跨站请求伪造)',
                        'severity': '中危',
                        'url': url,
                        'parameter': 'N/A',
                        'method': method,
                        'payload': '缺少CSRF验证',
                        'description': f'API端点 {url} 可能缺少CSRF保护,不要求CSRF相关请求头',
                        'recommendation': '为所有状态修改的API端点添加CSRF token验证。要求X-CSRF-Token或X-Requested-With头。使用SameSite Cookie属性'
                    })
        
        return vulnerabilities
    
    def _deduplicate_vulns(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """去重漏洞报告"""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            # 使用URL+类型去重
            key = (vuln['url'], vuln['type'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
