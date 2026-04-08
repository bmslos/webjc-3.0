#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
增强版核心扫描引擎 - 支持异步并发、动态插件加载和多种检测器
"""

import os
import time
import asyncio
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.crawler import EnhancedWebCrawler
from core.plugin_manager import PluginManager
from core.utils.http import HTTPUtils, AsyncHTTPUtils
from core.utils.logger import Logger
from core.config import SCAN_CONFIG, ASYNC_CONFIG, VULN_CONFIG


class EnhancedWebScanner:
    """增强版Web应用漏洞扫描器"""
    
    def __init__(self, target: str, timeout: int = 15, threads: int = 10,
                 output_dir: str = 'reports', cookies: Optional[Dict] = None,
                 headers: Optional[Dict] = None, enable_crawler: bool = True,
                 max_pages: int = 200, rate_limit: float = 0.1,
                 use_async: bool = True, plugin_dir: Optional[str] = None,
                 proxy: Optional[Dict] = None, auth_config: Optional[Dict] = None):
        """
        初始化扫描器
        
        Args:
            target: 扫描目标URL
            timeout: HTTP请求超时时间
            threads: 扫描线程数
            output_dir: 报告输出目录
            cookies: 认证Cookie
            headers: 自定义请求头
            enable_crawler: 是否启用爬虫
            max_pages: 爬虫最大爬取页面数
            rate_limit: 请求限速(秒)
            use_async: 是否使用异步模式
            plugin_dir: 插件目录
            proxy: 代理配置
            auth_config: 认证配置
        """
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.output_dir = output_dir
        self.enable_crawler = enable_crawler
        self.max_pages = max_pages
        self.use_async = use_async
        self.logger = Logger()
        
        # 初始化HTTP工具(支持同步和异步)
        self.http_sync = HTTPUtils(
            timeout=timeout,
            cookies=cookies,
            headers=headers,
            rate_limit=rate_limit,
            proxy=proxy
        )
        
        self.http_async = AsyncHTTPUtils(
            timeout=timeout,
            cookies=cookies,
            headers=headers,
            rate_limit=rate_limit,
            proxy=proxy
        )
        
        # 初始化插件管理器
        self.plugin_manager = PluginManager(plugin_dir)
        
        # 扫描结果
        self.results = {
            'target': target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': [],
            'scan_stats': {
                'urls_discovered': 0,
                'forms_discovered': 0,
                'params_discovered': 0,
                'pages_crawled': 0,
                'api_endpoints_discovered': 0
            }
        }
        
        # 爬虫发现的数据
        self.crawled_data = {
            'urls': [target],
            'forms': [],
            'params': [],
            'api_endpoints': [],
            'inputs': []
        }
    
    async def _crawl_async(self):
        """异步执行网站爬取"""
        if not self.enable_crawler:
            self.logger.info("爬虫功能已禁用,仅扫描目标URL")
            return
        
        self.logger.info("=" * 60)
        self.logger.info("阶段1: 网站爬取(增强版)")
        self.logger.info("=" * 60)
        
        crawler = EnhancedWebCrawler(
            target=self.target,
            http_utils=self.http_sync,
            max_pages=self.max_pages
        )
        
        try:
            crawled_data = await crawler.crawl()
            self.crawled_data = crawled_data
            
            # 更新统计信息
            self.results['scan_stats']['urls_discovered'] = len(crawled_data['urls'])
            self.results['scan_stats']['forms_discovered'] = len(crawled_data['forms'])
            self.results['scan_stats']['params_discovered'] = len(crawled_data['params'])
            self.results['scan_stats']['pages_crawled'] = len(crawler.visited_urls)
            self.results['scan_stats']['api_endpoints_discovered'] = len(crawled_data.get('api_endpoints', []))
        finally:
            await crawler.close()
    
    def _crawl_sync(self):
        """同步执行网站爬取(兼容模式)"""
        if not self.enable_crawler:
            self.logger.info("爬虫功能已禁用,仅扫描目标URL")
            return
        
        self.logger.info("=" * 60)
        self.logger.info("阶段1: 网站爬取")
        self.logger.info("=" * 60)
        
        # 使用同步爬虫作为fallback
        from core.crawler import WebCrawler  # 导入旧版爬虫
        
        crawler = WebCrawler(
            target=self.target,
            http_utils=self.http_sync,
            max_pages=self.max_pages
        )
        
        crawled_data = crawler.crawl()
        self.crawled_data = crawled_data
        
        # 更新统计信息
        self.results['scan_stats']['urls_discovered'] = len(crawled_data['urls'])
        self.results['scan_stats']['forms_discovered'] = len(crawled_data['forms'])
        self.results['scan_stats']['params_discovered'] = len(crawled_data['params'])
        self.results['scan_stats']['pages_crawled'] = len(crawler.visited_urls)
    
    async def _scan_async(self):
        """异步执行漏洞扫描"""
        self.logger.info("=" * 60)
        self.logger.info("阶段2: 漏洞扫描(异步并发)")
        self.logger.info("=" * 60)
        
        # 加载内置检测器
        detectors = self._load_builtin_detectors()
        
        # 加载插件检测器
        plugin_detectors = self._load_plugin_detectors()
        detectors.extend(plugin_detectors)
        
        # 创建信号量限制并发
        semaphore = asyncio.Semaphore(ASYNC_CONFIG['semaphore_limit'])
        
        async def scan_with_semaphore(detector):
            async with semaphore:
                try:
                    if hasattr(detector, 'scan_async'):
                        result = await detector.scan_async()
                    else:
                        # 在线程池中执行同步扫描
                        loop = asyncio.get_event_loop()
                        result = await loop.run_in_executor(None, detector.scan)
                    
                    if result:
                        self.results['vulnerabilities'].extend(result)
                        self.logger.info(
                            f"{detector.name} 检测完成,发现 {len(result)} 个漏洞"
                        )
                    else:
                        self.logger.info(
                            f"{detector.name} 检测完成,未发现漏洞"
                        )
                except Exception as e:
                    self.logger.error(f"{detector.name} 检测失败: {str(e)}")
        
        # 并发执行所有检测器
        tasks = [scan_with_detector(detector) for detector in detectors]
        await asyncio.gather(*tasks)
        
        # 按严重程度排序
        self._sort_vulnerabilities()
    
    def _scan_sync(self):
        """同步执行漏洞扫描"""
        self.logger.info("=" * 60)
        self.logger.info("阶段2: 漏洞扫描")
        self.logger.info("=" * 60)
        
        # 加载内置检测器
        detectors = self._load_builtin_detectors()
        
        # 加载插件检测器
        plugin_detectors = self._load_plugin_detectors()
        detectors.extend(plugin_detectors)
        
        # 使用线程池并行扫描
        completed = 0
        total = len(detectors)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_detector = {
                executor.submit(detector.scan): detector 
                for detector in detectors
            }
            
            for future in as_completed(future_to_detector):
                detector = future_to_detector[future]
                completed += 1
                
                try:
                    result = future.result()
                    if result:
                        self.results['vulnerabilities'].extend(result)
                        self.logger.info(
                            f"[{completed}/{total}] {detector.name} 检测完成,发现 {len(result)} 个漏洞"
                        )
                    else:
                        self.logger.info(
                            f"[{completed}/{total}] {detector.name} 检测完成,未发现漏洞"
                        )
                except Exception as e:
                    self.logger.error(f"[{completed}/{total}] {detector.name} 检测失败: {str(e)}")
        
        # 按严重程度排序
        self._sort_vulnerabilities()
    
    def _load_builtin_detectors(self) -> List:
        """加载内置检测器"""
        detectors = []
        
        # 根据配置动态加载检测器
        detector_mapping = {
            'sqli': 'SQLInjectionDetector',
            'xss': 'XSSDetector',
            'csrf': 'CSRFDetector',
            'directory_traversal': 'DirectoryTraversalDetector',
            'sensitive_files': 'SensitiveFilesDetector',
            'command_injection': 'CommandInjectionDetector',
            'security_headers': 'SecurityHeadersDetector',
            'ssrf': 'SSRFDetector',
            'file_upload': 'FileUploadDetector',
            'cors': 'CORSDetector',
            'weak_password': 'WeakPasswordDetector',
            'xxe': 'XXEDetector',
            'open_redirect': 'OpenRedirectDetector',
        }
        
        for config_key, class_name in detector_mapping.items():
            if not VULN_CONFIG.get(config_key, {}).get('enabled', True):
                continue
            
            try:
                # 延迟导入检测器
                module_name = f"core.detectors.{config_key}"
                module = __import__(module_name, fromlist=[class_name])
                detector_class = getattr(module, class_name)
                
                # 实例化检测器
                detector = detector_class(
                    target=self.target,
                    http=self.http_sync,
                    urls=self.crawled_data['urls'],
                    forms=self.crawled_data['forms'],
                    params=self.crawled_data['params'],
                    api_endpoints=self.crawled_data.get('api_endpoints', []),
                    inputs=self.crawled_data.get('inputs', [])
                )
                
                detectors.append(detector)
                self.logger.debug(f"已加载检测器: {detector.name}")
                
            except Exception as e:
                self.logger.warning(f"加载检测器失败 {class_name}: {str(e)}")
        
        self.logger.info(f"已加载 {len(detectors)} 个内置检测器")
        return detectors
    
    def _load_plugin_detectors(self) -> List:
        """加载插件检测器"""
        plugin_detectors = []
        
        try:
            plugins = self.plugin_manager.load_all_plugins()
            
            for plugin_name, plugin_class in plugins.items():
                try:
                    detector = plugin_class(
                        target=self.target,
                        http=self.http_sync,
                        urls=self.crawled_data['urls'],
                        forms=self.crawled_data['forms']
                    )
                    plugin_detectors.append(detector)
                    self.logger.info(f"已加载插件检测器: {plugin_name}")
                except Exception as e:
                    self.logger.error(f"实例化插件 {plugin_name} 失败: {str(e)}")
        except Exception as e:
            self.logger.warning(f"加载插件失败: {str(e)}")
        
        return plugin_detectors
    
    def _sort_vulnerabilities(self):
        """按严重程度排序漏洞"""
        severity_order = {'严重': 0, '高危': 1, '中危': 2, '低危': 3, '信息': 4}
        self.results['vulnerabilities'].sort(
            key=lambda x: severity_order.get(x.get('severity', ''), 5)
        )
    
    async def scan_async(self):
        """
        开始完整扫描(异步模式)
        """
        self.logger.info(f"开始扫描目标: {self.target}")
        self.logger.info(f"扫描模式: 异步并发")
        start_time = time.time()
        
        try:
            # 阶段1: 爬取网站
            await self._crawl_async()
            
            # 阶段2: 漏洞扫描
            await self._scan_async()
            
            elapsed_time = time.time() - start_time
            self.logger.info("=" * 60)
            self.logger.info(f"扫描完成! 总耗时: {elapsed_time:.2f}秒")
            self.logger.info(f"共发现 {len(self.results['vulnerabilities'])} 个漏洞")
            self.logger.info("=" * 60)
            
        except KeyboardInterrupt:
            self.logger.warning("扫描被用户中断")
        except Exception as e:
            self.logger.error(f"扫描过程中发生错误: {str(e)}")
            raise
        finally:
            await self.http_async.close()
    
    def scan(self):
        """
        开始完整扫描(同步/异步自动选择)
        """
        if self.use_async:
            # 使用异步模式
            asyncio.run(self.scan_async())
        else:
            # 使用同步模式
            self.logger.info(f"开始扫描目标: {self.target}")
            self.logger.info(f"扫描模式: 同步并发")
            start_time = time.time()
            
            try:
                # 阶段1: 爬取网站
                self._crawl_sync()
                
                # 阶段2: 漏洞扫描
                self._scan_sync()
                
                elapsed_time = time.time() - start_time
                self.logger.info("=" * 60)
                self.logger.info(f"扫描完成! 总耗时: {elapsed_time:.2f}秒")
                self.logger.info(f"共发现 {len(self.results['vulnerabilities'])} 个漏洞")
                self.logger.info("=" * 60)
                
            except KeyboardInterrupt:
                self.logger.warning("扫描被用户中断")
            except Exception as e:
                self.logger.error(f"扫描过程中发生错误: {str(e)}")
                raise
    
    def generate_report(self, format: str = 'html') -> str:
        """
        生成扫描报告
        
        Args:
            format: 报告格式('html', 'json', 'csv')
            
        Returns:
            报告文件路径
        """
        from core.utils.report import ReportGenerator
        
        # 创建输出目录
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        
        # 生成报告
        report_generator = ReportGenerator(self.output_dir)
        
        if format == 'json':
            report_path = report_generator.generate_json(self.results)
        elif format == 'csv':
            report_path = report_generator.generate_csv(self.results)
        else:
            report_path = report_generator.generate(self.results)
        
        return report_path
