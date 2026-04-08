#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web应用漏洞自动化扫描工具增强版主入口 - v3.0 Pro

增强功能:
- 异步并发架构(aiohttp)
- JavaScript渲染爬虫(Playwright)
- 动态插件加载系统
- 自动登录和会话管理
- 更全面的漏洞检测覆盖
- 配置化管理
"""

import argparse
import sys
import os
import asyncio
from typing import Dict, Optional


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(
        description='Web应用漏洞自动化扫描工具 v3.0 Pro (增强版)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 基础扫描(异步模式)
  python main.py -t http://example.com

  # 带认证扫描(手动Cookie)
  python main.py -t http://example.com --cookie "session=abc123"

  # 自动登录扫描
  python main.py -t http://example.com --auto-login --login-url http://example.com/login --username admin --password 123456

  # 使用代理扫描
  python main.py -t http://example.com --proxy http://127.0.0.1:8080

  # 禁用爬虫,仅扫描单个URL
  python main.py -t http://example.com --no-crawler

  # 同步模式扫描(兼容旧版)
  python main.py -t http://example.com --sync

  # 生成JSON格式报告
  python main.py -t http://example.com --report-format json

  # 自定义扫描参数
  python main.py -t http://example.com --threads 20 --max-pages 200 --rate-limit 0.1
        """
    )
    
    # 必需参数
    parser.add_argument('--target', '-t', required=True, help='扫描目标URL')
    
    # 扫描配置
    parser.add_argument('--timeout', '-T', type=int, default=15, help='HTTP请求超时时间(秒),默认15')
    parser.add_argument('--threads', '-n', type=int, default=10, help='扫描线程数,默认10')
    parser.add_argument('--max-pages', '-m', type=int, default=200, help='爬虫最大爬取页面数,默认200')
    parser.add_argument('--rate-limit', '-r', type=float, default=0.1, help='请求间隔(秒),默认0.1')
    
    # 认证
    parser.add_argument('--cookie', '-c', type=str, help='认证Cookie(格式: "name1=value1;name2=value2")')
    parser.add_argument('--header', '-H', action='append', help='自定义请求头(格式: "Header: Value"),可多次使用')
    parser.add_argument('--auth-token', type=str, help='认证Token(Bearer Token)')
    
    # 自动登录
    parser.add_argument('--auto-login', action='store_true', help='启用自动登录')
    parser.add_argument('--login-url', type=str, help='登录页面URL')
    parser.add_argument('--username', '-u', type=str, help='登录用户名')
    parser.add_argument('--password', '-p', type=str, help='登录密码')
    
    # 代理
    parser.add_argument('--proxy', type=str, help='HTTP代理地址(格式: http://127.0.0.1:8080)')
    
    # 功能开关
    parser.add_argument('--no-crawler', action='store_true', help='禁用爬虫功能,仅扫描目标URL')
    parser.add_argument('--sync', action='store_true', help='使用同步模式(默认异步)')
    parser.add_argument('--no-async', action='store_true', help='禁用异步模式')
    
    # 插件
    parser.add_argument('--plugin-dir', type=str, help='插件目录路径')
    parser.add_argument('--list-plugins', action='store_true', help='列出所有可用插件')
    
    # 输出配置
    parser.add_argument('--output', '-o', default='reports', help='报告输出目录,默认reports')
    parser.add_argument('--report-format', '-f', choices=['html', 'json', 'csv'], default='html', help='报告格式,默认html')
    parser.add_argument('--verbose', '-v', action='store_true', help='详细输出模式')
    parser.add_argument('--quiet', '-q', action='store_true', help='静默模式,仅输出报告路径')
    
    return parser.parse_args()


def parse_cookie(cookie_str: str) -> Dict[str, str]:
    """
    解析Cookie字符串
    
    Args:
        cookie_str: Cookie字符串
        
    Returns:
        Cookie字典
    """
    cookies = {}
    if not cookie_str:
        return cookies
    
    for item in cookie_str.split(';'):
        item = item.strip()
        if '=' in item:
            key, value = item.split('=', 1)
            cookies[key.strip()] = value.strip()
    
    return cookies


def parse_headers(header_list) -> Dict[str, str]:
    """
    解析请求头列表
    
    Args:
        header_list: 请求头列表
        
    Returns:
        请求头字典
    """
    headers = {}
    if not header_list:
        return headers
    
    for header in header_list:
        if ':' in header:
            key, value = header.split(':', 1)
            headers[key.strip()] = value.strip()
    
    return headers


def main():
    """主函数"""
    args = parse_args()
    
    # 导入日志和扫描器
    from core.utils.logger import Logger
    from core.scanner import EnhancedWebScanner
    
    # 初始化日志
    logger = Logger(verbose=args.verbose)
    
    # 静默模式减少输出
    if args.quiet:
        import logging
        logger.logger.setLevel(logging.WARNING)
    
    # 显示扫描配置
    if not args.quiet:
        logger.info("=" * 70)
        logger.info("Web应用漏洞自动化扫描工具 v3.0 Pro")
        logger.info("=" * 70)
        logger.info(f"扫描目标: {args.target}")
        logger.info(f"扫描模式: {'同步' if args.sync or args.no_async else '异步(推荐)'}")
        logger.info(f"线程数: {args.threads}")
        logger.info(f"请求超时: {args.timeout}秒")
        logger.info(f"请求限速: {args.rate_limit}秒")
        logger.info(f"爬虫功能: {'禁用' if args.no_crawler else '启用'}")
        if not args.no_crawler:
            logger.info(f"最大爬取页面: {args.max_pages}")
        logger.info(f"报告格式: {args.report_format.upper()}")
        if args.proxy:
            logger.info(f"代理: {args.proxy}")
        if args.auto_login:
            logger.info("自动登录: 启用")
        logger.info("=" * 70)
    
    # 解析认证信息
    cookies = parse_cookie(args.cookie)
    headers = parse_headers(args.header)
    
    if args.auth_token:
        headers['Authorization'] = f"Bearer {args.auth_token}"
    
    # 解析代理配置
    proxy = None
    if args.proxy:
        proxy = {
            'http': args.proxy,
            'https': args.proxy
        }
    
    # 解析自动登录配置
    auth_config = None
    if args.auto_login:
        auth_config = {
            'auto_login': {
                'enabled': True,
                'login_url': args.login_url or '',
                'username_field': 'username',
                'password_field': 'password',
                'credentials': {
                    'username': args.username or '',
                    'password': args.password or ''
                }
            }
        }
    
    try:
        # 初始化扫描器
        scanner = EnhancedWebScanner(
            target=args.target,
            timeout=args.timeout,
            threads=args.threads,
            output_dir=args.output,
            cookies=cookies if cookies else None,
            headers=headers if headers else None,
            enable_crawler=not args.no_crawler,
            max_pages=args.max_pages,
            rate_limit=args.rate_limit,
            use_async=not args.sync and not args.no_async,
            plugin_dir=args.plugin_dir,
            proxy=proxy,
            auth_config=auth_config
        )
        
        # 开始扫描
        if not args.quiet:
            logger.info("开始扫描...")
        
        scanner.scan()
        
        # 生成报告
        report_path = scanner.generate_report(format=args.report_format)
        
        if args.quiet:
            print(report_path)
        else:
            logger.info(f"扫描完成! 报告已生成: {report_path}")
        
    except KeyboardInterrupt:
        logger.warning("\n扫描被用户中断")
        sys.exit(130)
    except Exception as e:
        logger.error(f"扫描过程中发生错误: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
