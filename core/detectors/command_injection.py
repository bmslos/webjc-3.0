#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
命令注入检测器 - 检测系统命令注入漏洞
"""

import re
import time
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.config import VULN_CONFIG
from core.detectors.base import BaseDetector


class CommandInjectionDetector(BaseDetector):
    """命令注入检测器"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 **kwargs):
        """
        初始化命令注入检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
        """
        super().__init__(target, http, urls=urls, forms=forms, params=params, **kwargs)
        self.name = "命令注入"
        
        config = self._load_vuln_config('command_injection')
        self.payloads = config.get('payloads', [
            '| whoami', '; whoami', '&& whoami',
            '| id', '; id',
            '| ls -la', '; ls -la',
        ])
        self.detection_patterns = config.get('detection_patterns', [
            'root:', 'uid=', 'gid=', 'total', 'Directory of', 'bytes free'
        ])
    
    def scan(self) -> List[Dict]:
        """
        扫描命令注入漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始命令注入检测...")
        
        # 测试GET参数
        for url in self.urls[:50]:
            vulns = self._test_get_injection(url)
            vulnerabilities.extend(vulns)
            
            if len(vulnerabilities) > 10:
                break
        
        # 测试POST表单
        for form in self.forms[:10]:
            if form.get('method', 'GET').upper() == 'POST':
                vulns = self._test_post_injection(form)
                vulnerabilities.extend(vulns)
        
        return self._deduplicate_vulns(vulnerabilities)
    
    def _test_get_injection(self, url: str) -> List[Dict]:
        """测试GET参数的命令注入"""
        vulnerabilities = []
        
        if '?' not in url:
            return vulnerabilities
        
        # 提取参数
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        # 重点测试命令相关参数
        command_params = ['cmd', 'exec', 'command', 'ping', 'ip', 'host', 'lookup', 'trace', 'action', 'do']
        target_params = [p for p in query_params.keys() if p.lower() in command_params]
        
        if not target_params:
            target_params = list(query_params.keys())[:5]
        
        for param_name in target_params:
            for payload in self.payloads[:8]:  # 限制payload数量
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
                    if self._check_command_injection(response.text):
                        vulnerabilities.append({
                            'type': '命令注入',
                            'severity': '高危',
                            'url': test_url,
                            'parameter': param_name,
                            'method': 'GET',
                            'payload': payload,
                            'description': f'参数 {param_name} 存在命令注入漏洞,可执行系统命令',
                            'recommendation': '避免直接执行用户输入的系统命令。使用参数化API代替shell命令。对输入进行白名单验证。使用沙箱或容器隔离执行环境'
                        })
                        break  # 发现漏洞后停止测试当前参数
        
        return vulnerabilities
    
    def _test_post_injection(self, form: Dict) -> List[Dict]:
        """测试POST表单的命令注入"""
        vulnerabilities = []
        
        form_action = form.get('action', self.target)
        inputs = form.get('inputs', [])
        
        # 查找命令相关输入字段
        command_inputs = []
        for input_field in inputs:
            input_name = input_field.get('name', '').lower()
            if any(keyword in input_name for keyword in ['cmd', 'command', 'exec', 'ping', 'ip', 'host']):
                command_inputs.append(input_field.get('name'))
        
        # 测试每个命令输入字段
        for input_name in command_inputs:
            for payload in self.payloads[:6]:
                post_data = {input_name: payload}
                response = self.http.post(form_action, data=post_data)
                
                if response and response.status_code == 200:
                    if self._check_command_injection(response.text):
                        vulnerabilities.append({
                            'type': '命令注入',
                            'severity': '高危',
                            'url': form_action,
                            'parameter': input_name,
                            'method': 'POST',
                            'payload': payload,
                            'description': f'表单字段 {input_name} 存在命令注入漏洞',
                            'recommendation': '避免直接执行用户输入的系统命令。使用参数化API。对输入进行严格验证'
                        })
                        break
        
        return vulnerabilities
    
    def _check_command_injection(self, response_text: str) -> bool:
        """检查响应是否包含命令执行结果"""
        if not response_text:
            return False
        
        # 检查检测模式
        for pattern in self.detection_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # 额外检查:系统命令输出特征
        command_indicators = [
            r'uid=\d+\([^)]+\) gid=\d+\([^)]+\)',  # id命令输出
            r'total\s+\d+',  # ls -la输出
            r'Directory of\s+',  # dir命令输出
            r'\d+ bytes free',  # dir命令输出
            r'root:x:\d+:\d+:',  # /etc/passwd内容
            r'Apache.*Server',  # 系统信息
        ]
        
        for indicator in command_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                return True
        
        return False
