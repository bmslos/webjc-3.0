#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
弱密码检测器 - 检测登录表单的弱密码问题
"""

import re
from typing import Dict, List, Optional
from core.config import VULN_CONFIG
from core.utils.logger import Logger


class WeakPasswordDetector:
    """弱密码检测器"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 **kwargs):
        """
        初始化弱密码检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
        """
        self.name = "弱密码"
        self.target = target
        self.http = http
        self.urls = urls or [target]
        self.forms = forms or []
        self.params = params or []
        self.logger = Logger()
        
        config = VULN_CONFIG.get('weak_password', {})
        self.common_passwords = config.get('common_passwords', [
            'admin', 'password', '123456', '12345678',
            'admin123', 'root', 'test', 'guest'
        ])
        self.username_list = config.get('username_list', [
            'admin', 'administrator', 'root', 'test', 'user', 'guest'
        ])
        
        # 登录失败标识
        self.failure_indicators = [
            'invalid',
            'incorrect',
            'failed',
            '错误',
            '失败',
            '不正确',
            '不存在',
        ]
        
        # 登录成功标识
        self.success_indicators = [
            'welcome',
            'dashboard',
            'logout',
            '欢迎',
            '退出',
            '个人中心',
        ]
    
    def scan(self) -> List[Dict]:
        """
        扫描弱密码漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始弱密码检测...")
        
        # 发现登录表单
        login_forms = self._find_login_forms()
        
        # 测试每个登录表单
        for form in login_forms:
            vulns = self._test_weak_passwords(form)
            vulnerabilities.extend(vulns)
            
            # 限制测试数量,避免过多请求
            if len(vulnerabilities) > 5:
                break
        
        return self._deduplicate_vulns(vulnerabilities)
    
    def _find_login_forms(self) -> List[Dict]:
        """发现登录表单"""
        login_forms = []
        
        for form in self.forms:
            inputs = form.get('inputs', [])
            
            # 检查是否包含用户名和密码字段
            has_username = False
            has_password = False
            
            for input_field in inputs:
                input_name = input_field.get('name', '').lower()
                input_type = input_field.get('type', '').lower()
                
                # 检查用户名字段
                if any(keyword in input_name for keyword in ['user', 'username', 'email', 'login', 'account']):
                    has_username = True
                
                # 检查密码字段
                if input_type == 'password' or 'password' in input_name or 'passwd' in input_name:
                    has_password = True
            
            if has_username and has_password:
                login_forms.append(form)
        
        # 也检查常见的登录URL
        login_paths = ['/login', '/admin', '/wp-login.php', '/auth', '/signin', '/manager']
        for url in self.urls[:30]:
            if any(path in url.lower() for path in login_paths):
                # 创建一个虚拟表单
                virtual_form = {
                    'action': url,
                    'method': 'POST',
                    'inputs': [
                        {'name': 'username', 'type': 'text'},
                        {'name': 'password', 'type': 'password'}
                    ]
                }
                # 避免重复
                if not any(f.get('action') == url for f in login_forms):
                    login_forms.append(virtual_form)
        
        return login_forms[:5]  # 限制最多测试5个表单
    
    def _test_weak_passwords(self, form: Dict) -> List[Dict]:
        """测试弱密码"""
        vulnerabilities = []
        
        form_action = form.get('action', self.target)
        inputs = form.get('inputs', [])
        
        # 查找用户名和密码字段名
        username_field = 'username'
        password_field = 'password'
        
        for input_field in inputs:
            input_name = input_field.get('name', '').lower()
            input_type = input_field.get('type', '').lower()
            
            if any(keyword in input_name for keyword in ['user', 'username', 'email', 'login']):
                username_field = input_field.get('name')
            if input_type == 'password' or 'password' in input_name or 'passwd' in input_name:
                password_field = input_field.get('name')
        
        # 测试常见用户名密码组合
        test_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('test', 'test'),
            ('guest', 'guest'),
        ]
        
        # 添加配置中的组合
        for username in self.username_list[:3]:
            for password in self.common_passwords[:5]:
                test_credentials.append((username, password))
        
        # 去重
        test_credentials = list(set(test_credentials))
        
        # 测试每个凭证组合
        for username, password in test_credentials[:15]:  # 限制测试次数
            post_data = {
                username_field: username,
                password_field: password
            }
            
            response = self.http.post(form_action, data=post_data, allow_redirects=False)
            
            if response:
                # 检查是否登录成功
                if self._is_login_success(response, form_action):
                    vulnerabilities.append({
                        'type': '弱密码',
                        'severity': '高危',
                        'url': form_action,
                        'parameter': f'{username_field}/{password_field}',
                        'method': 'POST',
                        'payload': f'username: {username}, password: {password}',
                        'description': f'登录端点 {form_action} 存在弱密码,{username}:{password} 可成功登录',
                        'recommendation': '强制使用强密码策略(至少8位,包含大小写字母、数字和特殊字符)。实施账户锁定机制(连续5次失败锁定30分钟)。启用双因素认证。限制登录尝试次数'
                    })
                    break  # 发现弱密码后停止测试当前表单
        
        return vulnerabilities
    
    def _is_login_success(self, response, original_url: str) -> bool:
        """判断是否登录成功"""
        if not response:
            return False
        
        response_text = response.text.lower()
        
        # 检查重定向
        if response.status_code in [301, 302, 303]:
            location = response.headers.get('Location', '')
            # 如果重定向到dashboard/admin/home等页面,可能是成功
            if any(path in location.lower() for path in ['dashboard', 'admin', 'home', 'index', 'main']):
                return True
        
        # 检查响应内容
        if response.status_code == 200:
            # 检查成功标识
            has_success = any(indicator in response_text for indicator in self.success_indicators)
            
            # 检查失败标识
            has_failure = any(indicator in response_text for indicator in self.failure_indicators)
            
            # 如果有成功标识且没有失败标识,判断为成功
            if has_success and not has_failure:
                return True
            
            # 如果设置了新的session cookie,可能是成功
            set_cookie = response.headers.get('Set-Cookie', '')
            if set_cookie and any(keyword in set_cookie.lower() for keyword in ['session', 'auth', 'token', 'user']):
                if not has_failure:
                    return True
        
        return False
    
    def _deduplicate_vulns(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """去重漏洞报告"""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            # 使用URL去重
            key = vuln['url']
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
