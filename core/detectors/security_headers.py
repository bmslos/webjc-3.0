#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
安全头检测器 - 检测HTTP响应中缺失的安全头
"""

from typing import Dict, List, Optional
from core.config import VULN_CONFIG
from core.utils.logger import Logger


class SecurityHeadersDetector:
    """安全头检测器"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 **kwargs):
        """
        初始化安全头检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
        """
        self.name = "安全头检查"
        self.target = target
        self.http = http
        self.urls = urls or [target]
        self.forms = forms or []
        self.params = params or []
        self.logger = Logger()
        
        config = VULN_CONFIG.get('security_headers', {})
        self.required_headers = config.get('required_headers', [])
    
    def scan(self) -> List[Dict]:
        """
        扫描安全头缺失漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始安全头检测...")
        
        # 测试目标URL和发现的URL
        test_urls = list(set([self.target] + self.urls[:30]))
        
        for url in test_urls:
            response = self.http.get(url)
            if response and response.status_code == 200:
                vulns = self._check_missing_headers(url, response)
                vulnerabilities.extend(vulns)
                
                # 检查信息泄露
                vulns = self._check_info_disclosure(url, response)
                vulnerabilities.extend(vulns)
            
            # 限制测试数量
            if len(vulnerabilities) > 20:
                break
        
        return self._deduplicate_vulns(vulnerabilities)
    
    def _check_missing_headers(self, url: str, response) -> List[Dict]:
        """检查缺失的安全头"""
        vulnerabilities = []
        response_headers = {k.lower(): v for k, v in response.headers.items()}
        
        for header in self.required_headers:
            header_lower = header.lower()
            if header_lower not in response_headers:
                severity = self._get_severity(header)
                vulnerabilities.append({
                    'type': '安全头缺失',
                    'severity': severity,
                    'url': url,
                    'parameter': 'N/A',
                    'method': 'GET',
                    'payload': f'缺少: {header}',
                    'description': f'响应头缺少 {header} 安全头,可能降低网站安全性',
                    'recommendation': self._get_recommendation(header)
                })
            else:
                # 检查header值是否正确
                header_value = response_headers[header_lower]
                vuln = self._validate_header_value(header, header_value, url)
                if vuln:
                    vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _validate_header_value(self, header: str, value: str, url: str) -> Optional[Dict]:
        """验证安全头的值是否正确"""
        header_lower = header.lower()
        
        if header_lower == 'strict-transport-security':
            if 'max-age' not in value.lower():
                return {
                    'type': '安全头配置错误',
                    'severity': '中危',
                    'url': url,
                    'parameter': 'N/A',
                    'method': 'GET',
                    'payload': f'Strict-Transport-Security: {value}',
                    'description': 'HSTS头缺少max-age指令,HTTPS强制无效',
                    'recommendation': '设置Strict-Transport-Security头,max-age至少为31536000(1年),建议包含includeSubDomains指令'
                }
            if 'max-age=0' in value.lower():
                return {
                    'type': '安全头配置错误',
                    'severity': '中危',
                    'url': url,
                    'parameter': 'N/A',
                    'method': 'GET',
                    'payload': f'Strict-Transport-Security: {value}',
                    'description': 'HSTS头max-age设置为0,HSTS保护已禁用',
                    'recommendation': '设置Strict-Transport-Security头,max-age至少为31536000(1年)'
                }
        
        elif header_lower == 'x-frame-options':
            value_upper = value.upper()
            if value_upper not in ['DENY', 'SAMEORIGIN'] and not value_upper.startswith('ALLOW-FROM'):
                return {
                    'type': '安全头配置错误',
                    'severity': '中危',
                    'url': url,
                    'parameter': 'N/A',
                    'method': 'GET',
                    'payload': f'X-Frame-Options: {value}',
                    'description': 'X-Frame-Options头配置不正确,可能无法防止点击劫持',
                    'recommendation': '设置X-Frame-Options为DENY或SAMEORIGIN,或使用Content-Security-Policy的frame-ancestors指令'
                }
        
        elif header_lower == 'x-content-type-options':
            if value.lower() != 'nosniff':
                return {
                    'type': '安全头配置错误',
                    'severity': '低危',
                    'url': url,
                    'parameter': 'N/A',
                    'method': 'GET',
                    'payload': f'X-Content-Type-Options: {value}',
                    'description': 'X-Content-Type-Options头未设置为nosniff,MIME类型嗅探保护不足',
                    'recommendation': '设置X-Content-Type-Options: nosniff,防止浏览器进行MIME类型嗅探'
                }
        
        return None
    
    def _check_info_disclosure(self, url: str, response) -> List[Dict]:
        """检查信息泄露"""
        vulnerabilities = []
        response_headers = {k: v for k, v in response.headers.items()}
        
        # 检查Server头是否泄露版本信息
        if 'Server' in response_headers:
            server_value = response_headers['Server']
            if any(keyword in server_value.lower() for keyword in ['apache/', 'nginx/', 'iis/', 'php/', 'python']):
                vulnerabilities.append({
                    'type': '信息泄露',
                    'severity': '信息',
                    'url': url,
                    'parameter': 'N/A',
                    'method': 'GET',
                    'payload': f'Server: {server_value}',
                    'description': f'Server头泄露服务器软件版本信息: {server_value}',
                    'recommendation': '配置Web服务器移除或修改Server头,避免泄露具体版本信息'
                })
        
        # 检查X-Powered-By头
        if 'X-Powered-By' in response_headers:
            powered_by = response_headers['X-Powered-By']
            vulnerabilities.append({
                'type': '信息泄露',
                'severity': '信息',
                'url': url,
                'parameter': 'N/A',
                'method': 'GET',
                'payload': f'X-Powered-By: {powered_by}',
                'description': f'X-Powered-By头泄露技术栈信息: {powered_by}',
                'recommendation': '移除X-Powered-By头,避免泄露服务器使用的技术栈'
            })
        
        return vulnerabilities
    
    def _get_severity(self, header: str) -> str:
        """根据header类型返回严重程度"""
        critical_headers = ['Strict-Transport-Security', 'Content-Security-Policy']
        high_headers = ['X-Frame-Options', 'X-Content-Type-Options']
        medium_headers = ['X-XSS-Protection', 'Referrer-Policy', 'Permissions-Policy']
        
        if header in critical_headers:
            return '高危'
        elif header in high_headers:
            return '中危'
        elif header in medium_headers:
            return '低危'
        else:
            return '信息'
    
    def _get_recommendation(self, header: str) -> str:
        """返回针对缺失header的修复建议"""
        recommendations = {
            'Strict-Transport-Security': '添加Strict-Transport-Security头,设置max-age至少为31536000(1年),建议包含includeSubDomains指令。强制浏览器使用HTTPS连接',
            'Content-Security-Policy': '添加Content-Security-Policy头,配置适当的资源加载策略,防止XSS和数据注入攻击。建议使用default-src \'self\'',
            'X-Content-Type-Options': '添加X-Content-Type-Options: nosniff头,防止浏览器进行MIME类型嗅探,避免将非脚本文件作为脚本执行',
            'X-Frame-Options': '添加X-Frame-Options: DENY或SAMEORIGIN头,防止网站被嵌入到iframe中,避免点击劫持攻击',
            'X-XSS-Protection': '添加X-XSS-Protection: 1; mode=block头,启用浏览器内置XSS过滤器(仅对旧版浏览器有效)',
            'Referrer-Policy': '添加Referrer-Policy头,建议设置为strict-origin-when-cross-origin或no-referrer,控制Referer信息泄露',
            'Permissions-Policy': '添加Permissions-Policy头,限制危险API的使用,如geolocation、camera、microphone等',
            'Cache-Control': '添加Cache-Control头控制页面缓存策略,敏感页面应设置为no-store,防止敏感信息被缓存',
            'Pragma': '添加Pragma: no-cache头(HTTP/1.0兼容),确保代理服务器不缓存敏感页面',
        }
        return recommendations.get(header, f'添加{header}头以增强网站安全性')
    
    def _deduplicate_vulns(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """去重漏洞报告"""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            # 对安全头缺失,使用URL+header类型去重
            key = (vuln['url'], vuln.get('payload', ''), vuln['type'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
