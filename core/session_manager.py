#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
会话管理器 - 增强版,支持自动登录、Token刷新和多种认证方式
"""

import time
import json
from typing import Dict, Optional, Any
from urllib.parse import urljoin
from core.config import AUTH_CONFIG
from core.utils.http import HTTPUtils
from core.utils.logger import Logger


class SessionManager:
    """会话管理器 - 处理认证、登录和会话保持"""
    
    def __init__(self, http: HTTPUtils, auth_config: Optional[Dict] = None):
        """
        初始化会话管理器
        
        Args:
            http: HTTP工具实例
            auth_config: 认证配置
        """
        self.http = http
        self.auth_config = auth_config or AUTH_CONFIG
        self.logger = Logger()
        
        self.is_authenticated = False
        self.session_data = {
            'cookies': {},
            'headers': {},
            'token': None,
            'refresh_token': None,
            'expires_at': 0,
            'last_refresh': 0
        }
    
    def auto_login(self, login_url: Optional[str] = None, 
                   username: Optional[str] = None,
                   password: Optional[str] = None) -> bool:
        """
        自动登录
        
        Args:
            login_url: 登录URL
            username: 用户名
            password: 密码
            
        Returns:
            是否登录成功
        """
        auto_login_config = self.auth_config.get('auto_login', {})
        
        if not auto_login_config.get('enabled', False):
            self.logger.debug("自动登录未启用")
            return False
        
        # 使用提供的参数或配置中的默认值
        login_url = login_url or auto_login_config.get('login_url', '')
        username = username or auto_login_config['credentials'].get('username', '')
        password = password or auto_login_config['credentials'].get('password', '')
        
        if not login_url or not username or not password:
            self.logger.warning("登录信息不完整,无法执行自动登录")
            return False
        
        self.logger.info(f"正在执行自动登录: {login_url}")
        
        try:
            # 获取登录页面(可能需要先获取CSRF token)
            response = self.http.get(login_url)
            if not response:
                self.logger.error("无法访问登录页面")
                return False
            
            # 提取CSRF token(如果存在)
            csrf_token = self._extract_csrf_token(response.text)
            
            # 准备登录数据
            login_data = {
                auto_login_config.get('username_field', 'username'): username,
                auto_login_config.get('password_field', 'password'): password,
            }
            
            if csrf_token:
                login_data['csrf_token'] = csrf_token
                self.logger.debug("已提取CSRF token")
            
            # 发送登录请求
            login_response = self.http.post(
                login_url,
                data=login_data,
                allow_redirects=True
            )
            
            if not login_response:
                self.logger.error("登录请求失败")
                return False
            
            # 检查登录是否成功
            success = self._check_login_success(
                login_response.text,
                auto_login_config.get('success_indicators', []),
                auto_login_config.get('failure_indicators', [])
            )
            
            if success:
                self.is_authenticated = True
                
                # 保存会话信息
                self.session_data['cookies'] = dict(login_response.cookies)
                
                self.logger.info("登录成功!")
                self.logger.debug(f"获取到 {len(self.session_data['cookies'])} 个Cookie")
                
                # 提取并保存Token(如果存在)
                self._extract_and_save_token(login_response.text)
                
                return True
            else:
                self.logger.error("登录失败,请检查凭据或登录URL")
                return False
                
        except Exception as e:
            self.logger.error(f"自动登录过程中发生错误: {str(e)}")
            return False
    
    def refresh_token(self) -> bool:
        """
        刷新访问Token
        
        Returns:
            是否刷新成功
        """
        token_config = self.auth_config.get('token_refresh', {})
        
        if not token_config.get('enabled', False):
            self.logger.debug("Token刷新未启用")
            return False
        
        refresh_url = token_config.get('refresh_url', '')
        refresh_token = self.session_data.get('refresh_token')
        
        if not refresh_url or not refresh_token:
            self.logger.warning("缺少刷新URL或refresh_token")
            return False
        
        self.logger.info("正在刷新Token...")
        
        try:
            response = self.http.post(
                refresh_url,
                json={
                    'refresh_token': refresh_token,
                    'grant_type': 'refresh_token'
                }
            )
            
            if not response or response.status_code != 200:
                self.logger.error("Token刷新失败")
                return False
            
            # 解析新Token
            token_data = response.json()
            
            self.session_data['token'] = token_data.get(token_config.get('token_field', 'access_token'))
            self.session_data['refresh_token'] = token_data.get(token_config.get('refresh_token_field', 'refresh_token'))
            self.session_data['expires_at'] = time.time() + token_data.get('expires_in', 3600)
            self.session_data['last_refresh'] = time.time()
            
            # 更新Authorization header
            if self.session_data['token']:
                self.http.set_auth_token(self.session_data['token'])
            
            self.logger.info("Token刷新成功")
            return True
            
        except Exception as e:
            self.logger.error(f"Token刷新失败: {str(e)}")
            return False
    
    def oauth2_login(self, client_id: Optional[str] = None,
                     client_secret: Optional[str] = None) -> bool:
        """
        OAuth2认证
        
        Args:
            client_id: 客户端ID
            client_secret: 客户端密钥
            
        Returns:
            是否认证成功
        """
        oauth_config = self.auth_config.get('oauth2', {})
        
        if not oauth_config.get('enabled', False):
            self.logger.debug("OAuth2认证未启用")
            return False
        
        client_id = client_id or oauth_config.get('client_id', '')
        client_secret = client_secret or oauth_config.get('client_secret', '')
        token_url = oauth_config.get('token_url', '')
        scope = oauth_config.get('scope', '')
        
        if not client_id or not client_secret or not token_url:
            self.logger.warning("OAuth2配置不完整")
            return False
        
        self.logger.info(f"正在执行OAuth2认证: {token_url}")
        
        try:
            response = self.http.post(
                token_url,
                data={
                    'grant_type': 'client_credentials',
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'scope': scope
                }
            )
            
            if not response or response.status_code != 200:
                self.logger.error("OAuth2认证失败")
                return False
            
            token_data = response.json()
            
            self.session_data['token'] = token_data.get('access_token')
            self.session_data['expires_at'] = time.time() + token_data.get('expires_in', 3600)
            
            # 设置Authorization header
            if self.session_data['token']:
                self.http.set_auth_token(self.session_data['token'])
                self.is_authenticated = True
            
            self.logger.info("OAuth2认证成功")
            return True
            
        except Exception as e:
            self.logger.error(f"OAuth2认证失败: {str(e)}")
            return False
    
    def set_manual_auth(self, cookies: Optional[Dict] = None,
                        headers: Optional[Dict] = None,
                        token: Optional[str] = None):
        """
        手动设置认证信息
        
        Args:
            cookies: Cookie字典
            headers: 请求头字典
            token: Bearer Token
        """
        if cookies:
            self.http.set_cookies(cookies)
            self.session_data['cookies'].update(cookies)
        
        if headers:
            self.http.set_headers(headers)
            self.session_data['headers'].update(headers)
        
        if token:
            self.http.set_auth_token(token)
            self.session_data['token'] = token
            self.is_authenticated = True
        
        self.logger.info("已设置手动认证信息")
    
    def check_and_refresh(self) -> bool:
        """
        检查会话是否过期,并在需要时刷新
        
        Returns:
            会话是否有效
        """
        if not self.is_authenticated:
            return False
        
        # 检查Token是否即将过期
        if self.session_data.get('token') and self.session_data.get('expires_at'):
            time_left = self.session_data['expires_at'] - time.time()
            
            # 如果剩余时间少于60秒,刷新Token
            if time_left < 60:
                return self.refresh_token()
        
        return True
    
    def get_session_data(self) -> Dict[str, Any]:
        """获取当前会话数据"""
        return self.session_data.copy()
    
    def _extract_csrf_token(self, html: str) -> Optional[str]:
        """从HTML中提取CSRF token"""
        import re
        
        # 尝试多种常见的CSRF token名称
        csrf_patterns = [
            r'<input[^>]*name=["\']csrf_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'<input[^>]*name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'<input[^>]*name=["\']authenticity_token["\'][^>]*value=["\']([^"\']+)["\']',
            r'var csrf_token = ["\']([^"\']+)["\']',
        ]
        
        for pattern in csrf_patterns:
            match = re.search(pattern, html)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_and_save_token(self, html: str):
        """从HTML或JSON中提取并保存Token"""
        import re
        
        # 尝试从HTML中提取JWT token
        jwt_pattern = r'["\']?(?:access_token|token)["\']?\s*[:=]\s*["\']([eyJ][a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["\']'
        match = re.search(jwt_pattern, html)
        if match:
            self.session_data['token'] = match.group(1)
            self.logger.debug("已提取JWT token")
        
        # 尝试从LocalStorage风格的脚本中提取
        local_storage_pattern = r'localStorage\.setItem\(["\']token["\'],\s*["\']([^"\']+)["\']'
        match = re.search(local_storage_pattern, html)
        if match:
            self.session_data['token'] = match.group(1)
            self.logger.debug("已从LocalStorage模式提取token")
    
    def _check_login_success(self, response_text: str, 
                             success_indicators: list,
                             failure_indicators: list) -> bool:
        """
        检查登录是否成功
        
        Args:
            response_text: 响应文本
            success_indicators: 登录成功标识
            failure_indicators: 登录失败标识
            
        Returns:
            是否登录成功
        """
        response_lower = response_text.lower()
        
        # 检查失败标识
        for indicator in failure_indicators:
            if indicator.lower() in response_lower:
                self.logger.debug(f"检测到失败标识: {indicator}")
                return False
        
        # 检查成功标识
        for indicator in success_indicators:
            if indicator.lower() in response_lower:
                self.logger.debug(f"检测到成功标识: {indicator}")
                return True
        
        # 如果没有明确的标识,返回False
        self.logger.warning("无法确定登录状态,请检查响应内容")
        return False
