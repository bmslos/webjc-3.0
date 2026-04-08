#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQL注入检测器 - 增强版,支持错误回显、布尔盲注、时间盲注和Union注入
"""

import re
import time
import asyncio
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode
from core.config import VULN_CONFIG
from core.utils.logger import Logger


class SQLInjectionDetector:
    """SQL注入检测器 - 增强版"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 **kwargs):
        """
        初始化SQL注入检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
        """
        self.name = "SQL注入"
        self.target = target
        self.http = http
        self.urls = urls or [target]
        self.forms = forms or []
        self.params = params or []
        self.logger = Logger()
        
        config = VULN_CONFIG.get('sqli', {})
        self.payloads = config.get('payloads', [])
        self.error_patterns = config.get('error_patterns', [])
        self.boolean_payloads = config.get('boolean_payloads', [])
        self.time_payloads = config.get('time_payloads', [])
        self.time_threshold = config.get('time_threshold', 4.0)
    
    def scan(self) -> List[Dict]:
        """
        扫描SQL注入漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始SQL注入检测...")
        
        # 测试所有发现的URL
        for url in self.urls[:50]:  # 限制测试URL数量
            # 1. 错误回显检测
            vulns = self._test_error_based(url)
            vulnerabilities.extend(vulns)
            
            # 2. 布尔盲注检测
            vulns = self._test_boolean_based(url)
            vulnerabilities.extend(vulns)
            
            # 3. 时间盲注检测
            vulns = self._test_time_based(url)
            vulnerabilities.extend(vulns)
            
            # 如果已经发现漏洞,减少后续测试
            if len(vulnerabilities) > 10:
                break
        
        # 测试POST表单
        for form in self.forms[:10]:
            vulns = self._test_post_sqli(form)
            vulnerabilities.extend(vulns)
        
        # 去重
        return self._deduplicate_vulns(vulnerabilities)
    
    def _test_error_based(self, url: str) -> List[Dict]:
        """基于错误回显的SQL注入检测"""
        vulnerabilities = []
        
        # 只对带参数的URL进行测试
        if '?' not in url:
            # 尝试添加常见参数
            test_params = self.params[:10] if self.params else [
                'id', 'user', 'username', 'pass', 'password', 
                'query', 'search', 'q', 'uid', 'pid', 'cid', 'page'
            ]
            
            for param in test_params:
                test_url = f"{url}?{param}=1"
                response = self.http.get(test_url)
                if response and response.status_code == 200:
                    for payload in self.payloads:
                        test_url = f"{url}?{param}={payload}"
                        response = self.http.get(test_url)
                        
                        if response and self._check_sql_error(response.text):
                            vulnerabilities.append({
                                'type': 'SQL注入(错误回显)',
                                'severity': '高危',
                                'url': test_url,
                                'parameter': param,
                                'method': 'GET',
                                'payload': payload,
                                'description': f"参数 {param} 存在SQL注入漏洞(基于错误回显)",
                                'recommendation': "使用参数化查询或预编译语句,避免直接拼接SQL语句。对用户输入进行严格验证和转义。使用ORM框架。"
                            })
                            break
        else:
            parsed = urlparse(url)
            url_params = list(parse_qs(parsed.query).keys())
            
            for param in url_params:
                for payload in self.payloads[:5]:  # 使用前5个payload
                    test_url = f"{url.split('?')[0]}?{param}={payload}"
                    response = self.http.get(test_url)
                    
                    if response and self._check_sql_error(response.text):
                        vulnerabilities.append({
                            'type': 'SQL注入(错误回显)',
                            'severity': '高危',
                            'url': test_url,
                            'parameter': param,
                            'method': 'GET',
                            'payload': payload,
                            'description': f"参数 {param} 存在SQL注入漏洞(基于错误回显)",
                            'recommendation': "使用参数化查询或预编译语句,避免直接拼接SQL语句。"
                        })
                        break
        
        return vulnerabilities
    
    def _test_boolean_based(self, url: str) -> List[Dict]:
        """基于布尔盲注的SQL注入检测"""
        vulnerabilities = []
        
        if '?' not in url:
            return vulnerabilities
        
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        
        if not params:
            return vulnerabilities
        
        for param in params[:2]:  # 只测试前2个参数
            for true_payload, false_payload in self.boolean_payloads[:2]:
                # 发送正常请求
                normal_url = f"{url}?{param}=1"
                normal_resp = self.http.get(normal_url)
                
                if not normal_resp or normal_resp.status_code != 200:
                    continue
                
                # 发送TRUE条件请求
                true_url = f"{url}?{param}={true_payload}"
                true_resp = self.http.get(true_url)
                
                if not true_resp:
                    continue
                
                # 发送FALSE条件请求
                false_url = f"{url}?{param}={false_payload}"
                false_resp = self.http.get(false_url)
                
                if not false_resp:
                    continue
                
                # 比较响应内容
                normal_len = len(normal_resp.text)
                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                
                # 如果TRUE和FALSE响应明显不同
                if abs(true_len - false_len) > normal_len * 0.15:
                    if abs(true_len - normal_len) < abs(false_len - normal_len) * 0.6:
                        vulnerabilities.append({
                            'type': 'SQL注入(布尔盲注)',
                            'severity': '高危',
                            'url': url,
                            'parameter': param,
                            'method': 'GET',
                            'payload': f"TRUE: {true_payload}",
                            'description': f"参数 {param} 可能存在SQL注入漏洞(基于布尔盲注)",
                            'recommendation': "使用参数化查询或预编译语句,避免直接拼接SQL语句。"
                        })
                        break
        
        return vulnerabilities
    
    def _test_time_based(self, url: str) -> List[Dict]:
        """基于时间盲注的SQL注入检测"""
        vulnerabilities = []
        
        if '?' not in url:
            return vulnerabilities
        
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        
        if not params:
            return vulnerabilities
        
        for param in params[:2]:
            for sleep_payload in self.time_payloads[:3]:
                if 'SLEEP(5)' in sleep_payload or '00:00:05' in sleep_payload or 'pg_sleep(5)' in sleep_payload:
                    sleep_time = 5
                else:
                    continue
                
                test_url = f"{url.split('?')[0]}?{param}={sleep_payload}"
                
                # 发送请求并计时
                start_time = time.time()
                response = self.http.get(test_url)
                elapsed_time = time.time() - start_time
                
                if not response:
                    continue
                
                # 如果响应时间明显大于sleep时间
                if elapsed_time >= self.time_threshold:
                    vulnerabilities.append({
                        'type': 'SQL注入(时间盲注)',
                        'severity': '高危',
                        'url': test_url,
                        'parameter': param,
                        'method': 'GET',
                        'payload': sleep_payload,
                        'description': f"参数 {param} 可能存在SQL注入漏洞(基于时间盲注,响应时间: {elapsed_time:.2f}s)",
                        'recommendation': "使用参数化查询或预编译语句,避免直接拼接SQL语句。"
                    })
                    break
        
        return vulnerabilities
    
    def _test_post_sqli(self, form: Dict) -> List[Dict]:
        """测试POST型SQL注入"""
        vulnerabilities = []
        form_action = form.get('action', self.target)
        
        for input_field in form.get('inputs', [])[:5]:
            param = input_field.get('name')
            if not param:
                continue
            
            for payload in self.payloads[:3]:
                test_data = {param: payload}
                response = self.http.post(form_action, data=test_data)
                
                if response and self._check_sql_error(response.text):
                    vulnerabilities.append({
                        'type': 'SQL注入(POST型)',
                        'severity': '高危',
                        'url': form_action,
                        'parameter': param,
                        'method': 'POST',
                        'payload': payload,
                        'description': f"表单参数 {param} 可能存在SQL注入漏洞",
                        'recommendation': "使用参数化查询或预编译语句,对用户输入进行严格验证。"
                    })
                    break
        
        return vulnerabilities
    
    def _check_sql_error(self, response_text: str) -> bool:
        """检查响应中是否存在SQL错误信息"""
        response_lower = response_text.lower()
        for pattern in self.error_patterns:
            if pattern.lower() in response_lower:
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
