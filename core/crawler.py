#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
增强版网站爬虫 - 支持JavaScript渲染、API端点发现和更全面的爬取能力
"""

import re
import json
import asyncio
from collections import deque
from typing import Dict, List, Set, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse, urldefrag, parse_qs
from bs4 import BeautifulSoup
from core.config import CRAWLER_CONFIG
from core.utils.http import HTTPUtils, AsyncHTTPUtils
from core.utils.logger import Logger


class EnhancedWebCrawler:
    """增强版网站爬虫"""
    
    def __init__(self, target: str, http_utils: HTTPUtils, 
                 max_pages: int = 200, same_domain: bool = True,
                 use_playwright: bool = False):
        """
        初始化爬虫
        
        Args:
            target: 爬取目标URL
            http_utils: HTTP工具实例
            max_pages: 最大爬取页面数
            same_domain: 是否只爬取同域名
            use_playwright: 是否使用Playwright渲染JS
        """
        self.target = target
        self.http = http_utils
        self.max_pages = max_pages
        self.same_domain = same_domain
        self.use_playwright = use_playwright
        self.logger = Logger()
        
        self.visited_urls: Set[str] = set()
        self.urls_to_visit: deque = deque(
            [target], maxlen=CRAWLER_CONFIG.get('max_url_queue', 2000)
        )
        self.discovered_urls: List[str] = []
        self.discovered_forms: List[Dict] = []
        self.discovered_params: Set[str] = set()
        self.discovered_api_endpoints: List[Dict] = []
        self.discovered_inputs: List[Dict] = []
        
        self.target_domain = urlparse(target).netloc
        self.robots_urls: Set[str] = set()
        self.sitemap_urls: Set[str] = set()
        
        # Playwright相关
        self.playwright = None
        self.browser = None
    
    async def crawl(self) -> Dict[str, Any]:
        """
        开始爬取网站
        
        Returns:
            包含发现的URL、表单、参数和API端点的字典
        """
        self.logger.info(f"开始爬取网站: {self.target}")
        self.logger.info(f"最大爬取页面数: {self.max_pages}")
        
        # 解析robots.txt
        if CRAWLER_CONFIG.get('respect_robots_txt', True):
            await self._parse_robots_txt()
        
        # 解析sitemap
        if CRAWLER_CONFIG.get('parse_sitemap', True):
            await self._parse_sitemap()
        
        pages_crawled = 0
        
        while self.urls_to_visit and pages_crawled < self.max_pages:
            current_url = self.urls_to_visit.popleft()
            
            if current_url in self.visited_urls:
                continue
            
            self.visited_urls.add(current_url)
            pages_crawled += 1
            
            self.logger.info(f"[{pages_crawled}/{self.max_pages}] 正在爬取: {current_url}")
            
            try:
                # 根据配置选择爬取方式
                if self.use_playwright and pages_crawled <= 20:  # 前20页使用Playwright
                    await self._crawl_with_playwright(current_url)
                else:
                    await self._crawl_static(current_url)
                
            except Exception as e:
                self.logger.error(f"爬取失败 {current_url}: {str(e)}")
                continue
        
        self.logger.info(f"爬取完成! 共爬取 {pages_crawled} 个页面")
        self.logger.info(f"发现 {len(self.discovered_urls)} 个URL")
        self.logger.info(f"发现 {len(self.discovered_forms)} 个表单")
        self.logger.info(f"发现 {len(self.discovered_params)} 个参数")
        self.logger.info(f"发现 {len(self.discovered_api_endpoints)} 个API端点")
        
        return {
            'urls': self.discovered_urls,
            'forms': self.discovered_forms,
            'params': list(self.discovered_params),
            'api_endpoints': self.discovered_api_endpoints,
            'inputs': self.discovered_inputs
        }

    async def _async_get(self, url: str):
        """
        异步获取页面，兼容同步和异步HTTP工具

        当 http_utils 为 AsyncHTTPUtils 时直接 await；
        为同步 HTTPUtils 时通过 asyncio.to_thread 避免阻塞事件循环。
        """
        if isinstance(self.http, AsyncHTTPUtils):
            return await self.http.get(url)
        return await asyncio.to_thread(self.http.get, url)

    async def _crawl_static(self, url: str):
        """爬取静态页面"""
        response = await self._async_get(url)
        if not response or response.status_code != 200:
            return

        await self._parse_page(response.text, url)
    
    async def _crawl_with_playwright(self, url: str):
        """使用Playwright爬取JavaScript渲染的页面"""
        try:
            # 延迟导入Playwright
            from playwright.async_api import async_playwright
            
            if not self.browser:
                playwright = await async_playwright().start()
                self.browser = await playwright.chromium.launch(
                    headless=CRAWLER_CONFIG['playwright'].get('headless', True)
                )
            
            page = await self.browser.new_page(
                viewport=CRAWLER_CONFIG['playwright'].get('viewport', {'width': 1920, 'height': 1080})
            )
            
            await page.goto(
                url,
                wait_until=CRAWLER_CONFIG['playwright'].get('wait_until', 'networkidle'),
                timeout=CRAWLER_CONFIG['playwright'].get('timeout', 30000)
            )
            
            # 等待页面加载完成
            await page.wait_for_load_state('networkidle')
            
            # 获取渲染后的HTML
            html_content = await page.content()
            
            # 提取JavaScript动态添加的URL
            js_urls = await self._extract_js_urls(page)
            
            # 提取API调用
            api_calls = await self._intercept_api_calls(page)
            
            await page.close()
            
            # 解析页面内容
            await self._parse_page(html_content, url)
            
            # 添加JS发现的URL
            for js_url in js_urls:
                if self._should_crawl(js_url):
                    full_url = urljoin(url, js_url)
                    if full_url not in self.visited_urls and full_url not in self.urls_to_visit:
                        self.urls_to_visit.append(full_url)
            
            # 添加API端点
            self.discovered_api_endpoints.extend(api_calls)
            
        except ImportError:
            self.logger.warning("Playwright未安装,回退到静态爬取")
            await self._crawl_static(url)
        except Exception as e:
            self.logger.error(f"Playwright爬取失败 {url}: {str(e)}")
            await self._crawl_static(url)
    
    async def _extract_js_urls(self, page) -> List[str]:
        """提取JavaScript中的URL"""
        urls = []
        
        try:
            # 提取页面中的所有链接(包括JS动态添加的)
            links = await page.evaluate('''() => {
                const links = Array.from(document.querySelectorAll('a[href]'));
                return links.map(link => link.href);
            }''')
            urls.extend(links)
            
            # 提取img src
            images = await page.evaluate('''() => {
                const imgs = Array.from(document.querySelectorAll('img[src]'));
                return imgs.map(img => img.src);
            }''')
            urls.extend(images)
            
            # 提取script src
            scripts = await page.evaluate('''() => {
                const scripts = Array.from(document.querySelectorAll('script[src]'));
                return scripts.map(script => script.src);
            }''')
            urls.extend(scripts)
            
        except Exception as e:
            self.logger.debug(f"提取JS URL失败: {str(e)}")
        
        return urls
    
    async def _intercept_api_calls(self, page) -> List[Dict]:
        """拦截并记录API调用"""
        api_calls = []
        
        try:
            # 监听网络请求
            page.on('request', lambda request: self._on_request(request, api_calls))
            
            # 等待一段时间以捕获更多请求
            await page.wait_for_timeout(2000)
            
        except Exception as e:
            self.logger.debug(f"拦截API调用失败: {str(e)}")
        
        return api_calls
    
    def _on_request(self, request, api_calls: List[Dict]):
        """处理网络请求事件"""
        url = request.url
        
        # 只记录XHR和Fetch请求
        if request.resource_type in ['xhr', 'fetch']:
            api_calls.append({
                'url': url,
                'method': request.method,
                'resource_type': request.resource_type,
                'post_data': request.post_data
            })
    
    async def _parse_page(self, html_content: str, current_url: str):
        """
        解析页面内容
        
        Args:
            html_content: HTML内容
            current_url: 当前页面URL
        """
        soup = BeautifulSoup(html_content, 'html.parser')
        
        self.discovered_urls.append(current_url)
        
        # 提取链接
        self._extract_links(soup, current_url)
        
        # 提取表单
        self._extract_forms(soup, current_url)
        
        # 提取URL中的参数
        self._extract_params_from_url(current_url)
        
        # 提取输入字段
        self._extract_inputs(soup, current_url)
    
    def _extract_links(self, soup: BeautifulSoup, current_url: str):
        """提取页面中的所有链接"""
        for link_tag in soup.find_all('a', href=True):
            href = link_tag['href']
            absolute_url = urljoin(current_url, href)
            absolute_url, _ = urldefrag(absolute_url)
            
            if self._should_crawl(absolute_url):
                if absolute_url not in self.visited_urls and absolute_url not in self.urls_to_visit:
                    self.urls_to_visit.append(absolute_url)
    
    def _extract_forms(self, soup: BeautifulSoup, current_url: str):
        """提取页面中的所有表单"""
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(current_url, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'enctype': form.get('enctype', '')
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name', ''),
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required'),
                    'pattern': input_tag.get('pattern', '')
                }
                
                if input_info['name']:
                    form_data['inputs'].append(input_info)
                    self.discovered_inputs.append({
                        'url': form_data['action'],
                        'method': form_data['method'],
                        'input': input_info
                    })
            
            self.discovered_forms.append(form_data)
    
    def _extract_inputs(self, soup: BeautifulSoup, current_url: str):
        """提取页面中的所有输入字段(包括不在表单中的)"""
        for input_tag in soup.find_all(['input', 'textarea', 'select']):
            input_name = input_tag.get('name', '')
            if input_name:
                self.discovered_inputs.append({
                    'url': current_url,
                    'type': input_tag.get('type', 'text'),
                    'name': input_name,
                    'value': input_tag.get('value', ''),
                    'required': input_tag.has_attr('required')
                })
    
    def _extract_params_from_url(self, url: str):
        """从URL中提取参数名"""
        parsed = urlparse(url)
        if parsed.query:
            params = re.findall(r'([^&=]+)=', parsed.query)
            self.discovered_params.update(params)
    
    async def _parse_robots_txt(self):
        """解析robots.txt文件"""
        try:
            base_url = f"{urlparse(self.target).scheme}://{urlparse(self.target).netloc}"
            robots_url = urljoin(base_url, '/robots.txt')
            
            response = await self._async_get(robots_url)
            if response and response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    line = line.strip()
                    if line.startswith('Disallow:') or line.startswith('Allow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_url = urljoin(base_url, path)
                            self.robots_urls.add(full_url)
                
                self.logger.info(f"从robots.txt发现 {len(self.robots_urls)} 个URL")
                
                # 添加到待爬取列表
                for url in self.robots_urls:
                    if self._should_crawl(url):
                        if url not in self.visited_urls and url not in self.urls_to_visit:
                            self.urls_to_visit.append(url)
        except Exception as e:
            self.logger.debug(f"解析robots.txt失败: {str(e)}")
    
    async def _parse_sitemap(self):
        """解析sitemap.xml"""
        try:
            base_url = f"{urlparse(self.target).scheme}://{urlparse(self.target).netloc}"
            sitemap_url = urljoin(base_url, '/sitemap.xml')
            
            response = await self._async_get(sitemap_url)
            if response and response.status_code == 200:
                # 提取URL
                urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                self.sitemap_urls.update(urls)
                
                self.logger.info(f"从sitemap.xml发现 {len(self.sitemap_urls)} 个URL")
                
                # 添加到待爬取列表
                for url in self.sitemap_urls:
                    if self._should_crawl(url):
                        if url not in self.visited_urls and url not in self.urls_to_visit:
                            self.urls_to_visit.append(url)
        except Exception as e:
            self.logger.debug(f"解析sitemap.xml失败: {str(e)}")
    
    def _should_crawl(self, url: str) -> bool:
        """判断是否应该爬取该URL"""
        # 检查协议
        if not url.startswith(('http://', 'https://')):
            return False
        
        # 检查是否只爬取同域名
        if self.same_domain:
            url_domain = urlparse(url).netloc
            if url_domain != self.target_domain:
                return False
        
        # 排除静态文件
        static_extensions = CRAWLER_CONFIG.get('static_extensions', [])
        if any(url.lower().endswith(ext) for ext in static_extensions):
            return False
        
        return True
    
    async def close(self):
        """关闭浏览器"""
        if self.browser:
            await self.browser.close()
