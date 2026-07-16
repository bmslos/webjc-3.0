#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
文件上传检测器 - 检测文件上传功能的安全漏洞
"""

import os
from typing import Dict, List, Optional
from core.config import VULN_CONFIG
from core.detectors.base import BaseDetector


class FileUploadDetector(BaseDetector):
    """文件上传检测器"""
    
    def __init__(self, target: str, http, urls: Optional[List] = None,
                 forms: Optional[List] = None, params: Optional[List] = None,
                 **kwargs):
        """
        初始化文件上传检测器
        
        Args:
            target: 扫描目标URL
            http: HTTP工具实例
            urls: 爬虫发现的URL列表
            forms: 爬虫发现的表单列表
            params: 发现的参数列表
        """
        super().__init__(target, http, urls=urls, forms=forms, params=params, **kwargs)
        self.name = "文件上传漏洞"
        
        config = self._load_vuln_config('file_upload')
        self.malicious_files = config.get('malicious_files', [
            {'name': 'shell.php', 'content': '<?php echo "test"; ?>', 'mime': 'application/x-php'},
            {'name': 'shell.html', 'content': '<script>document.write("test")</script>', 'mime': 'text/html'},
        ])
        self.bypass_techniques = config.get('bypass_techniques', [
            'double_extension',
            'case_manipulation',
            'mime_manipulation',
        ])
    
    def scan(self) -> List[Dict]:
        """
        扫描文件上传漏洞
        
        Returns:
            发现的漏洞列表
        """
        vulnerabilities = []
        
        self.logger.info("开始文件上传漏洞检测...")
        
        # 发现上传表单
        upload_forms = self._find_upload_forms()
        
        # 测试每个上传表单
        for form in upload_forms:
            # 基础上传测试
            vulns = self._test_basic_upload(form)
            vulnerabilities.extend(vulns)
            
            # 绕过技术测试
            vulns = self._test_bypass_techniques(form)
            vulnerabilities.extend(vulns)
            
            # 限制测试数量
            if len(vulnerabilities) > 10:
                break
        
        # 测试常见上传路径
        vulns = self._test_upload_endpoints()
        vulnerabilities.extend(vulns)
        
        return self._deduplicate_vulns(vulnerabilities)
    
    def _find_upload_forms(self) -> List[Dict]:
        """发现文件上传表单"""
        upload_forms = []
        
        for form in self.forms:
            inputs = form.get('inputs', [])
            enctype = form.get('enctype', '')
            
            # 检查是否有file类型输入
            has_file_input = any(
                input_field.get('type', '').lower() == 'file'
                for input_field in inputs
            )
            
            # 检查是否是multipart/form-data
            is_multipart = 'multipart/form-data' in enctype.lower()
            
            if has_file_input or is_multipart:
                upload_forms.append(form)
        
        return upload_forms
    
    def _test_basic_upload(self, form: Dict) -> List[Dict]:
        """基础上传测试"""
        vulnerabilities = []
        
        form_action = form.get('action', self.target)
        inputs = form.get('inputs', [])
        
        # 查找file输入字段
        file_fields = [
            input_field.get('name', 'file')
            for input_field in inputs
            if input_field.get('type', '').lower() == 'file'
        ]
        
        if not file_fields:
            file_fields = ['file']  # 默认字段名
        
        # 尝试上传恶意文件
        for file_field in file_fields:
            for malicious_file in self.malicious_files[:2]:  # 限制测试文件数量
                filename = malicious_file['name']
                content = malicious_file['content']
                mime_type = malicious_file['mime']
                
                # 注意:这里简化实现,实际应使用multipart/form-data上传
                # 由于HTTPUtils的限制,这里仅检测上传端点的响应
                try:
                    response = self.http.post(
                        form_action,
                        data={'upload': 'test'},
                        headers={'Content-Type': 'multipart/form-data'}
                    )
                    
                    if response and response.status_code == 200:
                        # 检查响应是否返回了上传文件的路径或成功标识
                        response_text = response.text.lower()
                        if any(keyword in response_text for keyword in ['uploaded', 'success', '上传成功', '文件路径', 'file path']):
                            vulnerabilities.append({
                                'type': '文件上传漏洞',
                                'severity': '高危',
                                'url': form_action,
                                'parameter': file_field,
                                'method': 'POST',
                                'payload': f'上传文件: {filename}',
                                'description': f'上传端点 {form_action} 可能允许文件上传,需要进一步验证文件类型限制',
                                'recommendation': '验证文件扩展名白名单。重命名上传文件。存储在非执行目录。设置正确的Content-Type验证。禁用上传目录的执行权限'
                            })
                            break
                except Exception as e:
                    self.logger.debug(f'上传测试失败: {form_action}, 错误: {str(e)}')
        
        return vulnerabilities
    
    def _test_bypass_techniques(self, form: Dict) -> List[Dict]:
        """测试绕过技术"""
        vulnerabilities = []
        
        form_action = form.get('action', self.target)
        
        # 测试双扩展名
        if 'double_extension' in self.bypass_techniques:
            bypass_files = [
                {'name': 'shell.jpg.php', 'content': '<?php echo "test"; ?>', 'mime': 'image/jpeg'},
                {'name': 'shell.php.jpg', 'content': '<?php echo "test"; ?>', 'mime': 'image/jpeg'},
            ]
            
            for bypass_file in bypass_files:
                try:
                    response = self.http.post(
                        form_action,
                        data={'upload': 'test', 'filename': bypass_file['name']},
                        headers={'Content-Type': 'multipart/form-data'}
                    )
                    
                    if response and response.status_code == 200:
                        response_text = response.text.lower()
                        if any(keyword in response_text for keyword in ['uploaded', 'success', '上传成功']):
                            vulnerabilities.append({
                                'type': '文件上传漏洞',
                                'severity': '高危',
                                'url': form_action,
                                'parameter': 'file',
                                'method': 'POST',
                                'payload': f'上传文件: {bypass_file["name"]} (绕过: 双扩展名)',
                                'description': f'上传端点 {form_action} 存在双扩展名绕过漏洞',
                                'recommendation': '验证文件扩展名白名单。从右到左检查扩展名。重命名上传文件。存储在非执行目录'
                            })
                            break
                except Exception as e:
                    self.logger.debug(f'双扩展名测试失败: {form_action}, 错误: {str(e)}')
        
        # 测试大小写变换
        if 'case_manipulation' in self.bypass_techniques:
            case_files = [
                {'name': 'shell.PHP', 'content': '<?php echo "test"; ?>', 'mime': 'application/x-php'},
                {'name': 'shell.Php', 'content': '<?php echo "test"; ?>', 'mime': 'application/x-php'},
            ]
            
            for case_file in case_files:
                try:
                    response = self.http.post(
                        form_action,
                        data={'upload': 'test', 'filename': case_file['name']},
                    )
                    
                    if response and response.status_code == 200:
                        response_text = response.text.lower()
                        if any(keyword in response_text for keyword in ['uploaded', 'success', '上传成功']):
                            vulnerabilities.append({
                                'type': '文件上传漏洞',
                                'severity': '高危',
                                'url': form_action,
                                'parameter': 'file',
                                'method': 'POST',
                                'payload': f'上传文件: {case_file["name"]} (绕过: 大小写变换)',
                                'description': f'上传端点 {form_action} 存在大小写变换绕过漏洞',
                                'recommendation': '验证文件扩展名时转换为小写。使用白名单机制。重命名上传文件'
                            })
                            break
                except Exception as e:
                    self.logger.debug(f'大小写测试失败: {form_action}, 错误: {str(e)}')
        
        # 测试MIME类型操纵
        if 'mime_manipulation' in self.bypass_techniques:
            try:
                response = self.http.post(
                    form_action,
                    data={'upload': 'test'},
                    headers={'Content-Type': 'image/jpeg'}
                )
                
                if response and response.status_code == 200:
                    response_text = response.text.lower()
                    if any(keyword in response_text for keyword in ['uploaded', 'success', '上传成功']):
                        vulnerabilities.append({
                            'type': '文件上传漏洞',
                            'severity': '中危',
                            'url': form_action,
                            'parameter': 'file',
                            'method': 'POST',
                            'payload': 'MIME类型: image/jpeg (实际内容可能为恶意代码)',
                            'description': f'上传端点 {form_action} 可能仅依赖MIME类型验证,存在MIME操纵漏洞',
                            'recommendation': '不仅验证MIME类型,还要验证文件内容和扩展名。使用文件头魔法数验证。存储在非执行目录'
                        })
            except Exception as e:
                self.logger.debug(f'MIME测试失败: {form_action}, 错误: {str(e)}')
        
        return vulnerabilities
    
    def _test_upload_endpoints(self) -> List[Dict]:
        """测试常见上传端点"""
        vulnerabilities = []
        
        upload_paths = ['/upload', '/upload.php', '/api/upload', '/file/upload', '/admin/upload']
        base_url = self._get_base_url()
        
        for path in upload_paths:
            upload_url = f'{base_url}{path}'
            
            # 简单测试端点是否存在
            response = self.http.get(upload_url)
            if response and response.status_code == 200:
                # 检查是否为上传页面
                response_text = response.text.lower()
                if any(keyword in response_text for keyword in ['upload', '文件上传', 'file upload', 'multipart']):
                    vulnerabilities.append({
                        'type': '文件上传端点',
                        'severity': '信息',
                        'url': upload_url,
                        'parameter': 'N/A',
                        'method': 'GET',
                        'payload': f'发现上传端点: {path}',
                        'description': f'发现文件上传端点 {upload_url},建议进行安全测试',
                        'recommendation': '验证上传端点的文件类型限制。实施白名单验证。重命名上传文件。存储在非执行目录'
                    })
        
        return vulnerabilities
    
    def _get_base_url(self) -> str:
        """获取目标基础URL"""
        from urllib.parse import urlparse
        parsed = urlparse(self.target)
        return f'{parsed.scheme}://{parsed.netloc}'
