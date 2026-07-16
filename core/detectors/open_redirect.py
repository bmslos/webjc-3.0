#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
开放重定向检测器 - 检测未经验证的外部URL重定向漏洞
"""

from typing import Dict, List, Optional
from urllib.parse import urlparse, urljoin, urlencode
from core.config import VULN_CONFIG
from core.detectors.base import BaseDetector


class OpenRedirectDetector(BaseDetector):
    """开放重定向检测器"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 **kwargs):
        """
        初始化开放重定向检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
        """
        super().__init__(target, http, urls=urls, forms=forms, params=params, **kwargs)
        self.name = "开放重定向"
        
        config = self._load_vuln_config('open_redirect')
        self.payloads = config.get('payloads', [
            'http://evil.com',
            '//evil.com',
            '///evil.com',
            'http://localhost.evil.com',
            '%40evil.com',
            '/\\evil.com',
        ])
        self.redirect_params = config.get('redirect_params', [
            'url', 'redirect', 'redirect_to', 'next', 'return',
            'returnto', 'dest', 'destination'
        ])
    
    def scan(self) -> List[Dict]:
        """
        扫描开放重定向漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始开放重定向检测...")
        
        # 获取目标域名
        target_domain = urlparse(self.target).netloc
        
        # 测试所有URL
        for url in self.urls[:50]:
            vulns = self._test_url_redirect(url, target_domain)
            vulnerabilities.extend(vulns)
            
            # 限制测试数量
            if len(vulnerabilities) > 10:
                break
        
        # 测试表单
        for form in self.forms[:10]:
            if form.get('method', 'GET').upper() == 'POST':
                vulns = self._test_post_redirect(form, target_domain)
                vulnerabilities.extend(vulns)
        
        return self._deduplicate_vulns(vulnerabilities)
    
    def _test_url_redirect(self, url: str, target_domain: str) -> List[Dict]:
        """测试URL参数的重定向漏洞"""
        vulnerabilities = []
        
        # 如果URL已经有参数,测试重定向参数
        if '?' in url:
            # 提取基础URL
            base_url = url.split('?')[0]
            
            # 测试每个重定向参数
            for param in self.redirect_params:
                for payload in self.payloads:
                    test_url = f"{base_url}?{param}={payload}"
                    vuln = self._test_redirect(test_url, param, payload, target_domain)
                    if vuln:
                        vulnerabilities.append(vuln)
        else:
            # 主动添加重定向参数
            for param in self.redirect_params:
                for payload in self.payloads[:3]:  # 限制payload数量
                    test_url = f"{url}?{param}={payload}"
                    vuln = self._test_redirect(test_url, param, payload, target_domain)
                    if vuln:
                        vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _test_redirect(self, url: str, param: str, payload: str, target_domain: str) -> Optional[Dict]:
        """测试单个重定向"""
        try:
            response = self.http.get(url, allow_redirects=False)
            
            if not response:
                return None
            
            # 检查重定向状态码
            if response.status_code not in [301, 302, 303, 307, 308]:
                return None
            
            # 获取Location头
            location = response.headers.get('Location', '')
            if not location:
                return None
            
            # 解析Location,检查是否指向外部域名
            parsed_location = urlparse(location)
            location_domain = parsed_location.netloc
            
            # 检查是否指向不同的域名
            if location_domain and location_domain != target_domain:
                # 排除localhost的变体
                if 'evil.com' in location_domain or 'attacker' in location_domain:
                    return {
                        'type': '开放重定向',
                        'severity': '中危',
                        'url': url,
                        'parameter': param,
                        'method': 'GET',
                        'payload': payload,
                        'description': f'参数 {param} 存在开放重定向漏洞,可重定向到恶意网站 {location_domain}',
                        'recommendation': '验证重定向URL的域名是否在白名单内。使用相对路径代替绝对URL。避免使用用户可控的参数进行重定向。使用允许列表验证目标URL'
                    }
            
            # 检查协议相对URL (//evil.com)
            if location.startswith('//') and target_domain not in location:
                return {
                    'type': '开放重定向',
                    'severity': '中危',
                    'url': url,
                    'parameter': param,
                    'method': 'GET',
                    'payload': payload,
                    'description': f'参数 {param} 存在协议相对URL重定向漏洞,可重定向到任意域名',
                    'recommendation': '验证重定向URL的协议和域名。禁止使用协议相对URL。使用白名单验证目标URL'
                }
        
        except Exception as e:
            self.logger.debug(f'重定向测试失败: {url}, 错误: {str(e)}')
        
        return None
    
    def _test_post_redirect(self, form: Dict, target_domain: str) -> List[Dict]:
        """测试POST表单的重定向"""
        vulnerabilities = []
        
        form_action = form.get('action', self.target)
        inputs = form.get('inputs', [])
        
        # 查找重定向相关字段
        redirect_inputs = []
        for input_field in inputs:
            input_name = input_field.get('name', '').lower()
            if any(param in input_name for param in self.redirect_params):
                redirect_inputs.append(input_field.get('name'))
        
        # 测试每个重定向字段
        for input_name in redirect_inputs:
            for payload in self.payloads[:2]:
                # 构建POST数据
                post_data = {input_name: payload}
                
                try:
                    response = self.http.post(form_action, data=post_data, allow_redirects=False)
                    
                    if response and response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if location:
                            parsed_location = urlparse(location)
                            location_domain = parsed_location.netloc
                            
                            if location_domain and location_domain != target_domain:
                                if 'evil.com' in location_domain or 'attacker' in location_domain:
                                    vulnerabilities.append({
                                        'type': '开放重定向',
                                        'severity': '中危',
                                        'url': form_action,
                                        'parameter': input_name,
                                        'method': 'POST',
                                        'payload': payload,
                                        'description': f'表单字段 {input_name} 存在开放重定向漏洞',
                                        'recommendation': '验证重定向URL的域名是否在白名单内。使用相对路径。避免使用用户可控的参数进行重定向'
                                    })
                except Exception as e:
                    self.logger.debug(f'POST重定向测试失败: {form_action}, 错误: {str(e)}')
        
        return vulnerabilities
