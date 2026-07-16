#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
目录遍历检测器 - 检测路径遍历漏洞,可读取系统敏感文件
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.config import VULN_CONFIG
from core.detectors.base import BaseDetector


class DirectoryTraversalDetector(BaseDetector):
    """目录遍历检测器"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 **kwargs):
        """
        初始化目录遍历检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
        """
        super().__init__(target, http, urls=urls, forms=forms, params=params, **kwargs)
        self.name = "目录遍历"
        
        config = self._load_vuln_config('directory_traversal')
        self.payloads = config.get('payloads', ['../', '../../', '../../../'])
        self.test_files = config.get('test_files', ['etc/passwd', 'windows/win.ini'])
        
        # 文件内容特征
        self.file_signatures = {
            'etc/passwd': [r'root:x:', r'daemon:x:', r'nobody:x:'],
            'etc/shadow': [r'root:', r'shadow:'],
            'windows/win.ini': [r'\[fonts\]', r'\[extensions\]', r'\[mci extensions\]'],
            'windows/system32/drivers/etc/hosts': [r'127\.0\.0\.1\s+localhost'],
            'etc/hosts': [r'127\.0\.0\.1\s+localhost'],
        }
    
    def scan(self) -> List[Dict]:
        """
        扫描目录遍历漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始目录遍历检测...")
        
        # 测试GET参数
        for url in self.urls[:50]:
            vulns = self._test_get_traversal(url)
            vulnerabilities.extend(vulns)
            
            if len(vulnerabilities) > 10:
                break
        
        # 测试POST表单
        for form in self.forms[:10]:
            if form.get('method', 'GET').upper() == 'POST':
                vulns = self._test_post_traversal(form)
                vulnerabilities.extend(vulns)
        
        return self._deduplicate_vulns(vulnerabilities)
    
    def _test_get_traversal(self, url: str) -> List[Dict]:
        """测试GET参数的目录遍历"""
        vulnerabilities = []
        
        if '?' not in url:
            return vulnerabilities
        
        # 提取参数
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # 重点测试文件相关参数
        file_params = ['file', 'path', 'dir', 'doc', 'page', 'include', 'load', 'view']
        target_params = [p for p in query_params.keys() if p.lower() in file_params]
        
        if not target_params:
            target_params = list(query_params.keys())[:5]  # 限制测试前5个参数
        
        for param_name in target_params:
            for payload in self.payloads[:6]:  # 限制payload数量
                for test_file in self.test_files[:3]:  # 限制测试文件数量
                    full_payload = payload + test_file
                    
                    # 构建测试URL
                    test_params = query_params.copy()
                    test_params[param_name] = [full_payload]
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
                        if self._check_traversal_response(response.text, test_file):
                            vulnerabilities.append({
                                'type': '目录遍历',
                                'severity': '高危',
                                'url': test_url,
                                'parameter': param_name,
                                'method': 'GET',
                                'payload': full_payload,
                                'description': f'参数 {param_name} 存在目录遍历漏洞,可读取系统文件 {test_file}',
                                'recommendation': '对用户输入的文件路径进行严格验证。使用白名单机制允许特定文件。避免直接将用户输入传递给文件操作函数。使用chroot或沙箱环境'
                            })
                            break  # 发现漏洞后停止测试当前参数
                
                if vulnerabilities:
                    break
            if vulnerabilities:
                break
        
        return vulnerabilities
    
    def _test_post_traversal(self, form: Dict) -> List[Dict]:
        """测试POST表单的目录遍历"""
        vulnerabilities = []
        
        form_action = form.get('action', self.target)
        inputs = form.get('inputs', [])
        
        # 查找文件相关输入字段
        file_inputs = []
        for input_field in inputs:
            input_name = input_field.get('name', '').lower()
            if any(keyword in input_name for keyword in ['file', 'path', 'doc', 'page']):
                file_inputs.append(input_field.get('name'))
        
        # 测试每个文件输入字段
        for input_name in file_inputs:
            for payload in self.payloads[:4]:
                for test_file in self.test_files[:2]:
                    full_payload = payload + test_file
                    
                    post_data = {input_name: full_payload}
                    response = self.http.post(form_action, data=post_data)
                    
                    if response and response.status_code == 200:
                        if self._check_traversal_response(response.text, test_file):
                            vulnerabilities.append({
                                'type': '目录遍历',
                                'severity': '高危',
                                'url': form_action,
                                'parameter': input_name,
                                'method': 'POST',
                                'payload': full_payload,
                                'description': f'表单字段 {input_name} 存在目录遍历漏洞',
                                'recommendation': '对用户输入的文件路径进行严格验证。使用白名单机制。避免直接拼接用户输入到文件路径'
                            })
                            break
                
                if vulnerabilities:
                    break
            if vulnerabilities:
                break
        
        return vulnerabilities
    
    def _check_traversal_response(self, response_text: str, test_file: str) -> bool:
        """检查响应是否包含目标文件内容"""
        if not response_text:
            return False
        
        # 根据测试文件检查特征
        if test_file in self.file_signatures:
            signatures = self.file_signatures[test_file]
            for signature in signatures:
                if re.search(signature, response_text, re.IGNORECASE):
                    return True
        
        # 通用检查:响应包含典型的系统文件内容
        general_indicators = [
            r'root:x:\d+:\d+:',
            r'\[fonts\]',
            r'127\.0\.0\.1\s+localhost',
        ]
        
        for indicator in general_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                return True
        
        return False
