#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
增强版HTTP请求工具 - 支持异步、认证、重试、限速和代理
"""

import time
import asyncio
import ssl
import threading
from typing import Dict, Optional, Any, Union
from urllib.parse import urlparse

import aiohttp
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from core.config import HTTP_CONFIG, ASYNC_CONFIG
from core.utils.logger import Logger


class HTTPUtils:
    """同步HTTP请求工具类"""
    
    def __init__(self, timeout: int = 15, cookies: Optional[Dict] = None, 
                 headers: Optional[Dict] = None, rate_limit: float = 0.1, 
                 max_retries: int = 3, proxy: Optional[Dict] = None):
        """
        初始化HTTP工具
        
        Args:
            timeout: 超时时间(秒)
            cookies: 认证Cookie
            headers: 自定义请求头
            rate_limit: 请求间隔(秒)
            max_retries: 最大重试次数
            proxy: 代理配置
        """
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.logger = Logger()
        self._rate_lock = threading.Lock()

        # 创建Session
        self.session = requests.Session()
        
        # 设置默认headers
        default_headers = HTTP_CONFIG['default_headers'].copy()
        default_headers['User-Agent'] = HTTP_CONFIG['user_agent']
        if headers:
            default_headers.update(headers)
        self.session.headers.update(default_headers)
        
        # 设置Cookie(用于认证)
        if cookies:
            self.session.cookies.update(cookies)
        
        # 配置代理
        if proxy:
            self.session.proxies.update(proxy)
        
        # 配置重试策略
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=HTTP_CONFIG.get('retry_backoff', 1.5),
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
    
    def _apply_rate_limit(self):
        """应用请求限速（线程安全）"""
        if self.rate_limit > 0:
            with self._rate_lock:
                current_time = time.time()
                elapsed = current_time - self.last_request_time
                if elapsed < self.rate_limit:
                    sleep_time = self.rate_limit - elapsed
                    time.sleep(sleep_time)
                self.last_request_time = time.time()
    
    def get(self, url: str, headers: Optional[Dict] = None, 
            params: Optional[Dict] = None, allow_redirects: bool = True):
        """
        发送GET请求
        
        Args:
            url: 请求URL
            headers: 请求头
            params: URL参数
            allow_redirects: 是否允许重定向
            
        Returns:
            Response: 响应对象
        """
        self._apply_rate_limit()
        
        try:
            response = self.session.get(
                url, 
                headers=headers, 
                params=params, 
                timeout=self.timeout, 
                allow_redirects=allow_redirects
            )
            return response
        except requests.exceptions.Timeout:
            self.logger.debug(f"请求超时: {url}")
            return None
        except requests.exceptions.ConnectionError:
            self.logger.debug(f"连接错误: {url}")
            return None
        except Exception as e:
            self.logger.debug(f"请求失败: {url}, 错误: {str(e)}")
            return None
    
    def post(self, url: str, data: Optional[Dict] = None, 
             json: Optional[Dict] = None, headers: Optional[Dict] = None, 
             allow_redirects: bool = True):
        """
        发送POST请求
        
        Args:
            url: 请求URL
            data: 表单数据
            json: JSON数据
            headers: 请求头
            allow_redirects: 是否允许重定向
            
        Returns:
            Response: 响应对象
        """
        self._apply_rate_limit()
        
        try:
            response = self.session.post(
                url, 
                data=data, 
                json=json, 
                headers=headers, 
                timeout=self.timeout, 
                allow_redirects=allow_redirects
            )
            return response
        except requests.exceptions.Timeout:
            self.logger.debug(f"请求超时: {url}")
            return None
        except requests.exceptions.ConnectionError:
            self.logger.debug(f"连接错误: {url}")
            return None
        except Exception as e:
            self.logger.debug(f"请求失败: {url}, 错误: {str(e)}")
            return None
    
    def put(self, url: str, data: Optional[Dict] = None, 
            json: Optional[Dict] = None, headers: Optional[Dict] = None):
        """发送PUT请求"""
        self._apply_rate_limit()
        try:
            return self.session.put(url, data=data, json=json, headers=headers, timeout=self.timeout)
        except Exception as e:
            self.logger.debug(f"PUT请求失败: {url}, 错误: {str(e)}")
            return None
    
    def delete(self, url: str, headers: Optional[Dict] = None):
        """发送DELETE请求"""
        self._apply_rate_limit()
        try:
            return self.session.delete(url, headers=headers, timeout=self.timeout)
        except Exception as e:
            self.logger.debug(f"DELETE请求失败: {url}, 错误: {str(e)}")
            return None
    
    def set_cookies(self, cookies: Dict):
        """设置认证Cookie"""
        self.session.cookies.update(cookies)
    
    def set_headers(self, headers: Dict):
        """设置自定义请求头"""
        self.session.headers.update(headers)
    
    def set_auth_token(self, token: str, token_type: str = 'Bearer'):
        """设置认证Token"""
        self.session.headers['Authorization'] = f"{token_type} {token}"
    
    def update_user_agent(self, user_agent: str):
        """更新User-Agent"""
        self.session.headers['User-Agent'] = user_agent
    
    def close(self):
        """关闭Session"""
        self.session.close()

    def __enter__(self):
        """同步上下文管理器入口"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """同步上下文管理器退出，自动关闭Session"""
        self.close()


class AsyncHTTPUtils:
    """异步HTTP请求工具类 - 支持高并发"""
    
    def __init__(self, timeout: int = 15, cookies: Optional[Dict] = None,
                 headers: Optional[Dict] = None, rate_limit: float = 0.1,
                 max_retries: int = 3, proxy: Optional[Dict] = None):
        """
        初始化异步HTTP工具
        
        Args:
            timeout: 超时时间(秒)
            cookies: 认证Cookie
            headers: 自定义请求头
            rate_limit: 请求间隔(秒)
            max_retries: 最大重试次数
            proxy: 代理配置
        """
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.logger = Logger()
        self.max_retries = max_retries
        self._rate_lock = asyncio.Lock()
        
        # 配置connector
        allow_insecure = ASYNC_CONFIG.get('allow_insecure', False)
        if allow_insecure:
            # 仅在显式配置时禁用SSL验证（如自签名证书的内网测试）
            ssl_ctx = False
        else:
            # 默认启用SSL证书验证，防止MITM攻击
            ssl_ctx = ssl.create_default_context()

        connector = aiohttp.TCPConnector(
            limit=ASYNC_CONFIG['connection_pool_size'],
            limit_per_host=ASYNC_CONFIG['max_conn_per_host'],
            enable_cleanup_closed=True,
            ssl=ssl_ctx
        )
        
        # 配置默认headers
        default_headers = HTTP_CONFIG['default_headers'].copy()
        default_headers['User-Agent'] = HTTP_CONFIG['user_agent']
        if headers:
            default_headers.update(headers)
        
        # 配置Cookie
        cookie_jar = None
        if cookies:
            cookie_jar = aiohttp.CookieJar()
            cookie_jar.update_cookies(cookies)
        
        # 配置代理
        self.proxy = None
        if proxy and proxy.get('http'):
            self.proxy = proxy['http']
        
        # 创建session
        self.session = aiohttp.ClientSession(
            connector=connector,
            headers=default_headers,
            cookie_jar=cookie_jar,
            timeout=aiohttp.ClientTimeout(total=timeout)
        )
    
    async def _apply_rate_limit(self):
        """应用请求限速（协程安全）"""
        if self.rate_limit > 0:
            async with self._rate_lock:
                current_time = time.time()
                elapsed = current_time - self.last_request_time
                if elapsed < self.rate_limit:
                    sleep_time = self.rate_limit - elapsed
                    await asyncio.sleep(sleep_time)
                self.last_request_time = time.time()
    
    async def _request_with_retry(self, method: str, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """带重试的请求"""
        for attempt in range(self.max_retries + 1):
            try:
                await self._apply_rate_limit()
                
                async with self.session.request(method, url, **kwargs) as response:
                    # 读取响应内容以保持连接
                    await response.read()
                    return response
            except asyncio.TimeoutError:
                self.logger.debug(f"请求超时(尝试{attempt+1}): {url}")
                if attempt == self.max_retries:
                    return None
                await asyncio.sleep(2 ** attempt)
            except aiohttp.ClientError as e:
                self.logger.debug(f"请求失败(尝试{attempt+1}): {url}, 错误: {str(e)}")
                if attempt == self.max_retries:
                    return None
                await asyncio.sleep(2 ** attempt)
            except Exception as e:
                self.logger.debug(f"请求异常(尝试{attempt+1}): {url}, 错误: {str(e)}")
                if attempt == self.max_retries:
                    return None
                await asyncio.sleep(2 ** attempt)
        return None
    
    async def get(self, url: str, headers: Optional[Dict] = None,
                  params: Optional[Dict] = None, allow_redirects: bool = True):
        """发送异步GET请求"""
        return await self._request_with_retry(
            'GET', url, headers=headers, params=params,
            allow_redirects=allow_redirects
        )
    
    async def post(self, url: str, data: Optional[Dict] = None,
                   json: Optional[Dict] = None, headers: Optional[Dict] = None,
                   allow_redirects: bool = True):
        """发送异步POST请求"""
        return await self._request_with_retry(
            'POST', url, data=data, json=json, headers=headers,
            allow_redirects=allow_redirects
        )
    
    async def put(self, url: str, data: Optional[Dict] = None,
                  json: Optional[Dict] = None, headers: Optional[Dict] = None):
        """发送异步PUT请求"""
        return await self._request_with_retry('PUT', url, data=data, json=json, headers=headers)
    
    async def delete(self, url: str, headers: Optional[Dict] = None):
        """发送异步DELETE请求"""
        return await self._request_with_retry('DELETE', url, headers=headers)
    
    async def set_cookies(self, cookies: Dict):
        """设置Cookie"""
        self.session.cookie_jar.update_cookies(cookies)
    
    async def set_headers(self, headers: Dict):
        """设置请求头"""
        self.session.headers.update(headers)
    
    async def set_auth_token(self, token: str, token_type: str = 'Bearer'):
        """设置认证Token"""
        self.session.headers['Authorization'] = f"{token_type} {token}"
    
    async def close(self):
        """关闭Session"""
        if self.session and not self.session.closed:
            await self.session.close()

    async def __aenter__(self):
        """异步上下文管理器入口"""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """异步上下文管理器退出，自动关闭Session"""
        await self.close()
