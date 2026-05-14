#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
增强版核心扫描引擎 - 支持异步并发、动态插件加载、全局去重、二次验证和AI分析
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
from core.config import (
    SCAN_CONFIG, ASYNC_CONFIG, VULN_CONFIG,
    DEDUP_CONFIG, VERIFICATION_CONFIG, AI_CONFIG,
)
from core.dedup_engine import DedupEngine
from core.verification import VerificationEngine
from core.ai_analyzer import AIAnalyzer


class EnhancedWebScanner:
    """
    增强版Web应用漏洞扫描器

    扫描流程:
    1. 网站爬取 → 发现URL、表单、参数、API端点
    2. 漏洞扫描 → 13+检测器并发执行
    3. 全局去重 → 三层交叉去重（精确/输入点/根因）
    4. 二次验证 → 可疑漏洞重新确认，降低误报
    5. AI分析 → LLM误报过滤 + 智能payload生成
    6. 报告生成 → HTML/JSON/CSV多格式输出
    """

    def __init__(self, target: str, timeout: int = 15, threads: int = 10,
                 output_dir: str = 'reports', cookies: Optional[Dict] = None,
                 headers: Optional[Dict] = None, enable_crawler: bool = True,
                 max_pages: int = 200, rate_limit: float = 0.1,
                 use_async: bool = True, plugin_dir: Optional[str] = None,
                 proxy: Optional[Dict] = None, auth_config: Optional[Dict] = None,
                 enable_dedup: bool = True, enable_verification: bool = True,
                 enable_ai: bool = False, ai_config: Optional[Dict] = None,
                 task_id: Optional[str] = None):
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
            enable_dedup: 是否启用全局交叉去重
            enable_verification: 是否启用二次验证
            enable_ai: 是否启用AI分析
            ai_config: AI分析配置字典
            task_id: 关联的任务ID（用于任务持久化）
        """
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.output_dir = output_dir
        self.enable_crawler = enable_crawler
        self.max_pages = max_pages
        self.use_async = use_async
        self.logger = Logger()
        self.task_id = task_id

        self.http_sync = HTTPUtils(
            timeout=timeout,
            cookies=cookies,
            headers=headers,
            rate_limit=rate_limit,
            proxy=proxy
        )

        self.http_async = None
        self._async_config = {
            'timeout': timeout,
            'cookies': cookies,
            'headers': headers,
            'rate_limit': rate_limit,
            'proxy': proxy
        }

        self.plugin_manager = PluginManager(plugin_dir)

        self.enable_dedup = enable_dedup and DEDUP_CONFIG.get('enabled', True)
        self.dedup_engine = DedupEngine() if self.enable_dedup else None

        self.enable_verification = (
            enable_verification and VERIFICATION_CONFIG.get('enabled', True)
        )
        self.verification_engine = (
            VerificationEngine(self.http_sync) if self.enable_verification else None
        )

        effective_ai_config = ai_config or AI_CONFIG.copy()
        if enable_ai or AI_CONFIG.get('enabled', False):
            self.enable_ai = True
            self.ai_analyzer = AIAnalyzer(config=effective_ai_config)
        else:
            self.enable_ai = False
            self.ai_analyzer = None

        self.results = {
            'target': target,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': [],
            'scan_stats': {
                'urls_discovered': 0,
                'forms_discovered': 0,
                'params_discovered': 0,
                'pages_crawled': 0,
                'api_endpoints_discovered': 0,
            },
            'dedup_stats': {},
            'verification_stats': {},
            'ai_stats': {},
        }

        self.crawled_data = {
            'urls': [target],
            'forms': [],
            'params': [],
            'api_endpoints': [],
            'inputs': [],
        }

    def _init_async_http(self):
        """延迟初始化异步HTTP工具,避免事件循环问题"""
        if self.http_async is None:
            self.http_async = AsyncHTTPUtils(**self._async_config)

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

        crawler = EnhancedWebCrawler(
            target=self.target,
            http_utils=self.http_sync,
            max_pages=self.max_pages
        )

        try:
            crawled_data = asyncio.run(crawler.crawl())
            self.crawled_data = crawled_data

            self.results['scan_stats']['urls_discovered'] = len(crawled_data['urls'])
            self.results['scan_stats']['forms_discovered'] = len(crawled_data['forms'])
            self.results['scan_stats']['params_discovered'] = len(crawled_data['params'])
            self.results['scan_stats']['pages_crawled'] = len(crawler.visited_urls)
            self.results['scan_stats']['api_endpoints_discovered'] = len(crawled_data.get('api_endpoints', []))
        finally:
            asyncio.run(crawler.close())

    async def _scan_async(self):
        """异步执行漏洞扫描"""
        self.logger.info("=" * 60)
        self.logger.info("阶段2: 漏洞扫描(异步并发)")
        self.logger.info("=" * 60)

        detectors = self._load_builtin_detectors()
        plugin_detectors = self._load_plugin_detectors()
        detectors.extend(plugin_detectors)

        semaphore = asyncio.Semaphore(ASYNC_CONFIG['semaphore_limit'])

        async def scan_with_semaphore(detector):
            async with semaphore:
                try:
                    if hasattr(detector, 'scan_async'):
                        result = await detector.scan_async()
                    else:
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

        tasks = [scan_with_semaphore(detector) for detector in detectors]
        await asyncio.gather(*tasks)

        self._sort_vulnerabilities()

    def _scan_sync(self):
        """同步执行漏洞扫描"""
        self.logger.info("=" * 60)
        self.logger.info("阶段2: 漏洞扫描")
        self.logger.info("=" * 60)

        detectors = self._load_builtin_detectors()
        plugin_detectors = self._load_plugin_detectors()
        detectors.extend(plugin_detectors)

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

        self._sort_vulnerabilities()

    def _post_process(self):
        """
        后处理流水线

        对扫描结果依次执行:
        1. 全局交叉去重
        2. 二次验证
        3. AI误报过滤
        """
        raw_count = len(self.results['vulnerabilities'])

        if raw_count == 0:
            self.logger.info("=" * 60)
            self.logger.info("未发现漏洞, 跳过后处理阶段")
            self.logger.info("=" * 60)
            return

        # 阶段3: 全局交叉去重
        if self.enable_dedup and self.dedup_engine:
            self.logger.info("=" * 60)
            self.logger.info(f"阶段3: 全局交叉去重 ({raw_count} 条记录)")
            self.logger.info("=" * 60)
            self.results['vulnerabilities'] = self.dedup_engine.deduplicate(
                self.results['vulnerabilities']
            )
            self.results['dedup_stats'] = self.dedup_engine.get_stats()
            self.logger.info(
                f"去重完成: {raw_count} -> {len(self.results['vulnerabilities'])} 条"
            )

        after_dedup = len(self.results['vulnerabilities'])
        if after_dedup == 0:
            self.logger.info("去重后无剩余漏洞, 跳过验证和AI分析")
            return

        # 阶段4: 二次验证
        if self.enable_verification and self.verification_engine:
            self.logger.info("=" * 60)
            self.logger.info(f"阶段4: 二次验证 ({after_dedup} 条记录)")
            self.logger.info("=" * 60)
            self.results['vulnerabilities'] = self.verification_engine.verify_batch(
                self.results['vulnerabilities']
            )
            self.results['verification_stats'] = self.verification_engine.get_stats()

            before_filter = len(self.results['vulnerabilities'])
            self.results['vulnerabilities'] = [
                v for v in self.results['vulnerabilities']
                if v.get('verification_status', '') != 'rejected'
                and v.get('verification_status', '') != 'rejected_by_rule'
            ]
            after_filter = len(self.results['vulnerabilities'])
            if before_filter != after_filter:
                self.logger.info(
                    f"验证过滤: 移除 {before_filter - after_filter} 条误报"
                )

        after_verify = len(self.results['vulnerabilities'])
        if after_verify == 0:
            self.logger.info("验证后无剩余漏洞, 跳过AI分析")
            return

        # 阶段5: AI误报过滤
        if self.enable_ai and self.ai_analyzer:
            self.logger.info("=" * 60)
            self.logger.info("阶段5: AI误报过滤")
            self.logger.info("=" * 60)

            before_ai = len(self.results['vulnerabilities'])
            self.results['vulnerabilities'] = self.ai_analyzer.filter_false_positives(
                self.results['vulnerabilities']
            )

            ai_rejected = sum(
                1 for v in self.results['vulnerabilities']
                if v.get('ai_analysis', {}).get('is_false_positive', False)
            )
            self.results['vulnerabilities'] = [
                v for v in self.results['vulnerabilities']
                if not v.get('ai_analysis', {}).get('is_false_positive', False)
            ]
            self.results['ai_stats'] = {
                'total_analyzed': before_ai,
                'false_positives_filtered': ai_rejected,
                'remaining': len(self.results['vulnerabilities']),
            }
            self.logger.info(
                f"AI过滤完成: 移除 {ai_rejected} 条误报"
            )

        self._sort_vulnerabilities()

    def _load_builtin_detectors(self) -> List:
        """加载内置检测器"""
        detectors = []

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
                module_name = f"core.detectors.{config_key}"
                module = __import__(module_name, fromlist=[class_name])
                detector_class = getattr(module, class_name)

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

        流程: 爬取 → 扫描 → 去重 → 验证 → AI分析
        """
        self._init_async_http()

        self.logger.info(f"开始扫描目标: {self.target}")
        self.logger.info(f"扫描模式: 异步并发")
        start_time = time.time()

        try:
            await self._crawl_async()
            await self._scan_async()
            self._post_process()

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
            if self.http_async:
                await self.http_async.close()

    def scan(self):
        """
        开始完整扫描(同步/异步自动选择)

        流程: 爬取 → 扫描 → 去重 → 验证 → AI分析
        """
        if self.use_async:
            asyncio.run(self.scan_async())
        else:
            self.logger.info(f"开始扫描目标: {self.target}")
            self.logger.info(f"扫描模式: 同步并发")
            start_time = time.time()

            try:
                self._crawl_sync()
                self._scan_sync()
                self._post_process()

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

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

        report_generator = ReportGenerator(self.output_dir)

        if format == 'json':
            report_path = report_generator.generate_json(self.results)
        elif format == 'csv':
            report_path = report_generator.generate_csv(self.results)
        else:
            report_path = report_generator.generate(self.results)

        return report_path
