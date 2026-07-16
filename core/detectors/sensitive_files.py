#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
敏感文件检测器 - 检测可公开访问的敏感文件和目录
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urljoin, urlparse
from core.config import VULN_CONFIG
from core.detectors.base import BaseDetector


class SensitiveFilesDetector(BaseDetector):
    """敏感文件检测器"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 **kwargs):
        """
        初始化敏感文件检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
        """
        super().__init__(target, http, urls=urls, forms=forms, params=params, **kwargs)
        self.name = "敏感文件泄露"
        
        config = self._load_vuln_config('sensitive_files')
        self.sensitive_files = config.get('files', [])
        
        # 文件特征匹配规则
        self.file_patterns = {
            '.env': [r'DB_PASSWORD', r'SECRET_KEY', r'API_KEY', r'DATABASE_URL'],
            '.git/config': [r'\[core\]', r'\[remote', r'url\s*=', r'branch\s*\.'],
            'config': [r'define\s*\(', r'\$db', r'\$config', r'password\s*=', r'db_host'],
            'web.config': [r'<configuration>', r'<connectionStrings>', r'<system.web>'],
            '.htaccess': [r'RewriteEngine', r'Options', r'AuthType', r'Require'],
            'backup': [r'CREATE TABLE', r'INSERT INTO', r'DUMP', r'-- MySQL'],
            'phpinfo': [r'PHP Version', r'phpinfo\(\)', r'Configuration File'],
            'swagger': [r'swagger', r'openapi', r'paths', r'schemas'],
        }
    
    def scan(self) -> List[Dict]:
        """
        扫描敏感文件泄露漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始敏感文件检测...")
        
        # 获取目标基础URL
        base_url = self._get_base_url()
        
        # 测试每个敏感文件
        for file_path in self.sensitive_files:
            # 构建完整URL
            if file_path.startswith('http'):
                test_url = file_path
            else:
                # 移除开头的/
                file_path = file_path.lstrip('/')
                test_url = urljoin(base_url, file_path)
            
            # 发送请求
            response = self.http.get(test_url, allow_redirects=False)
            
            if response:
                # 检查是否可访问
                if response.status_code == 200:
                    # 检查响应内容是否为有效内容(非404页面)
                    if self._is_valid_content(response):
                        severity = self._get_severity(file_path)
                        description = self._get_description(file_path, response)
                        
                        vulnerabilities.append({
                            'type': '敏感文件泄露',
                            'severity': severity,
                            'url': test_url,
                            'parameter': 'N/A',
                            'method': 'GET',
                            'payload': f'直接访问: {file_path}',
                            'description': description,
                            'recommendation': self._get_recommendation(file_path)
                        })
                
                # 检查目录列表
                elif response.status_code in [301, 302]:
                    # 检查重定向目标
                    location = response.headers.get('Location', '')
                    if location:
                        redirect_url = urljoin(test_url, location)
                        redirect_response = self.http.get(redirect_url)
                        if redirect_response and redirect_response.status_code == 200:
                            if self._is_directory_listing(redirect_response):
                                vulnerabilities.append({
                                    'type': '目录列表泄露',
                                    'severity': '中危',
                                    'url': test_url,
                                    'parameter': 'N/A',
                                    'method': 'GET',
                                    'payload': f'访问目录: {file_path}',
                                    'description': f'目录 {file_path} 启用了目录列表,可浏览所有文件',
                                    'recommendation': '禁用Web服务器的目录列表功能。Apache: 移除Options +Indexes或使用Options -Indexes。Nginx: 设置autoindex off'
                                })
        
        return self._deduplicate_vulns(vulnerabilities)
    
    def _get_base_url(self) -> str:
        """获取目标基础URL"""
        parsed = urlparse(self.target)
        return f'{parsed.scheme}://{parsed.netloc}'
    
    def _is_valid_content(self, response) -> bool:
        """检查响应是否为有效内容(非404页面或空页面)"""
        body = response.text
        if not body:
            return False

        # 检查响应长度
        if len(body) < 50:
            return False

        # 检查常见的404页面特征
        text_lower = body.lower()
        if any(keyword in text_lower for keyword in ['404 not found', 'page not found', 'not found']):
            # 进一步检查HTTP状态码
            if response.status_code == 404:
                return False
        
        return True
    
    def _is_directory_listing(self, response) -> bool:
        """检查是否为目录列表"""
        text = response.text.lower()
        # 检查常见的目录列表特征
        directory_indicators = [
            'index of',
            'directory listing',
            'last modified',
            '<pre>',
            'parent directory',
        ]
        
        # 至少匹配2个指标
        match_count = sum(1 for indicator in directory_indicators if indicator in text)
        return match_count >= 2
    
    def _get_severity(self, file_path: str) -> str:
        """根据文件类型返回严重程度"""
        critical_files = ['.env', '.git/config', 'database', 'backup.sql', 'dump.sql']
        high_files = ['config.php', 'config.yml', 'config.json', 'web.config', '.htaccess', 'wp-config']
        medium_files = ['phpinfo', 'server-status', 'server-info', 'status', 'swagger', 'api-docs']
        
        file_lower = file_path.lower()
        if any(cf in file_lower for cf in critical_files):
            return '高危'
        elif any(hf in file_lower for hf in high_files):
            return '高危'
        elif any(mf in file_lower for mf in medium_files):
            return '中危'
        else:
            return '低危'
    
    def _get_description(self, file_path: str, response) -> str:
        """生成描述信息"""
        file_lower = file_path.lower()
        body = response.text

        # 检测可能泄露的内容类型
        content_types = []
        if any(pattern in body for pattern in ['password', 'passwd', 'secret', 'key']):
            content_types.append('密码或密钥')
        if any(pattern in body for pattern in ['CREATE TABLE', 'INSERT INTO', 'SELECT']):
            content_types.append('数据库信息')
        if any(pattern in body for pattern in ['api_key', 'token', 'authorization']):
            content_types.append('API凭证')
        if any(pattern in body for pattern in ['user', 'email', 'username']):
            content_types.append('用户信息')
        if any(pattern in body for pattern in ['PHP Version', 'Server API', 'Configuration']):
            content_types.append('服务器配置')
        
        if content_types:
            content_desc = '、'.join(content_types[:3])
            return f'敏感文件 {file_path} 可公开访问,可能泄露{content_desc}'
        else:
            return f'敏感文件 {file_path} 可公开访问,可能泄露敏感信息'
    
    def _get_recommendation(self, file_path: str) -> str:
        """返回修复建议"""
        file_lower = file_path.lower()
        
        if '.git' in file_lower:
            return '删除Web根目录下的.git目录。配置Web服务器拒绝访问隐藏文件(以.开头的文件)。使用.gitignore管理敏感文件。立即轮换所有可能泄露的凭证'
        elif '.env' in file_lower:
            return '删除或限制访问.env文件。将敏感配置存储在Web根目录外。使用密钥管理服务。立即轮换所有可能泄露的密码和API密钥'
        elif 'backup' in file_lower or 'dump' in file_lower:
            return '删除公开可访问的数据库备份文件。将备份存储在Web根目录外。加密备份文件。使用访问控制限制备份下载'
        elif 'config' in file_lower:
            return '将配置文件移到Web根目录外。设置正确的文件权限。使用环境变量存储敏感配置。禁止直接访问配置文件'
        else:
            return '删除或限制访问敏感文件。配置Web服务器拒绝访问隐藏文件和敏感文件。使用访问控制列表。定期审计Web目录中的敏感文件'
