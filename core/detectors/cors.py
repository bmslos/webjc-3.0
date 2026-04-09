#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CORS错误配置检测器 - 检测跨域资源共享配置问题
"""

from typing import Dict, List, Optional
from core.config import VULN_CONFIG
from core.utils.logger import Logger


class CORSDetector:
    """CORS错误配置检测器"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 api_endpoints: Optional[List] = None, **kwargs):
        """
        初始化CORS检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
            api_endpoints: API端点列表
        """
        self.name = "CORS错误配置"
        self.target = target
        self.http = http
        self.urls = urls or [target]
        self.forms = forms or []
        self.params = params or []
        self.api_endpoints = api_endpoints or []
        self.logger = Logger()
        
        config = VULN_CONFIG.get('cors', {})
        self.test_origins = config.get('test_origins', ['https://evil.com'])
    
    def scan(self) -> List[Dict]:
        """
        扫描CORS错误配置漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始CORS错误配置检测...")
        
        # 测试目标URL和API端点
        test_urls = list(set([self.target] + self.urls[:20] + [ep.get('url', '') for ep in self.api_endpoints[:10]]))
        test_urls = [url for url in test_urls if url]
        
        for url in test_urls:
            # 测试每个恶意Origin
            for origin in self.test_origins:
                vulns = self._test_cors(url, origin)
                vulnerabilities.extend(vulns)
            
            # 限制测试数量
            if len(vulnerabilities) > 10:
                break
        
        return self._deduplicate_vulns(vulnerabilities)
    
    def _test_cors(self, url: str, origin: str) -> List[Dict]:
        """测试CORS配置"""
        vulnerabilities = []
        
        # 发送带Origin头的请求
        headers = {
            'Origin': origin,
            'Access-Control-Request-Method': 'GET',
            'Access-Control-Request-Headers': 'Content-Type',
        }
        
        response = self.http.get(url, headers=headers)
        if not response:
            return vulnerabilities
        
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        
        # 检查Access-Control-Allow-Origin
        acao = response_headers.get('access-control-allow-origin', '')
        acac = response_headers.get('access-control-allow-credentials', '')
        
        if not acao:
            return vulnerabilities
        
        # 测试1: Origin反射(允许任意源)
        if acao == origin:
            severity = '高危' if acac.lower() == 'true' else '中危'
            vulnerabilities.append({
                'type': 'CORS错误配置',
                'severity': severity,
                'url': url,
                'parameter': 'Origin头',
                'method': 'GET',
                'payload': f'Origin: {origin}',
                'description': f'CORS配置允许 {origin} 跨域访问,Access-Control-Allow-Origin反射请求源',
                'recommendation': '使用明确的源列表代替反射Origin。验证Origin头是否在白名单内。不要同时设置ACAO=*和Allow-Credentials=true'
            })
        
        # 测试2: 通配符*且允许Credentials
        elif acao == '*' and acac.lower() == 'true':
            vulnerabilities.append({
                'type': 'CORS错误配置',
                'severity': '高危',
                'url': url,
                'parameter': 'Origin头',
                'method': 'GET',
                'payload': 'Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true',
                'description': 'CORS配置使用通配符*且允许Credentials,任何网站都可以发起带凭证的请求',
                'recommendation': '不要同时设置Access-Control-Allow-Origin: *和Access-Control-Allow-Credentials: true。使用明确的源列表'
            })
        
        # 测试3: null源允许
        elif acao.lower() == 'null':
            vulnerabilities.append({
                'type': 'CORS错误配置',
                'severity': '中危',
                'url': url,
                'parameter': 'Origin头',
                'method': 'GET',
                'payload': 'Origin: null',
                'description': 'CORS配置允许null源跨域访问,sandbox iframe可以利用',
                'recommendation': '拒绝null源的跨域请求。使用明确的源列表。验证Origin头是否在白名单内'
            })
        
        # 测试4: 子域名通配符
        elif '*' in acao and acao != '*':
            vulnerabilities.append({
                'type': 'CORS错误配置',
                'severity': '中危',
                'url': url,
                'parameter': 'Origin头',
                'method': 'GET',
                'payload': f'Access-Control-Allow-Origin: {acao}',
                'description': f'CORS配置使用子域名通配符 {acao},可能被恶意子域名利用',
                'recommendation': '避免使用通配符匹配子域名。使用明确的完整源列表。验证Origin头是否完全匹配'
            })
        
        return vulnerabilities
    
    def _deduplicate_vulns(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """去重漏洞报告"""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            # 使用URL+漏洞类型去重
            key = (vuln['url'], vuln['type'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
