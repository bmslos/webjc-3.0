#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web应用漏洞自动化扫描工具增强版主入口 - v3.0 Pro

增强功能:
- 异步并发架构(aiohttp)
- JavaScript渲染爬虫(Playwright)
- 动态插件加载系统
- 自动登录和会话管理
- 全局交叉去重引擎
- 二次验证与上下文理解
- AI误报过滤与智能payload生成
- 多目标批量扫描与任务持久化
"""

import argparse
import sys
import os
import asyncio
from typing import Dict, Optional, List


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

  # 多目标批量扫描
  python main.py -T targets.txt

  # 启用AI分析
  python main.py -t http://example.com --enable-ai --ai-api-key "your-key"

  # 禁用去重和验证
  python main.py -t http://example.com --no-dedup --no-verify

  # 查看任务列表
  python main.py --list-tasks

  # 查看任务统计
  python main.py --task-stats
        """
    )

    # 目标参数（单目标或多目标二选一）
    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument('--target', '-t', help='扫描目标URL(单目标)')
    target_group.add_argument(
        '--targets', '-T',
        help='扫描目标文件路径(多目标,每行一个URL)'
    )

    # 扫描配置
    parser.add_argument('--timeout', type=int, default=15, help='HTTP请求超时时间(秒),默认15')
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

    # 去重和验证开关
    parser.add_argument('--no-dedup', action='store_true', help='禁用全局交叉去重')
    parser.add_argument('--no-verify', action='store_true', help='禁用二次验证')

    # AI分析
    parser.add_argument('--enable-ai', action='store_true', help='启用AI分析(误报过滤+智能payload)')
    parser.add_argument('--ai-api-key', type=str, help='LLM API密钥(也可通过环境变量LLM_API_KEY设置)')
    parser.add_argument('--ai-api-base', type=str, help='LLM API基础URL')
    parser.add_argument('--ai-model', type=str, help='LLM模型名称(默认gpt-4o-mini)')

    # 插件
    parser.add_argument('--plugin-dir', type=str, help='插件目录路径')
    parser.add_argument('--list-plugins', action='store_true', help='列出所有可用插件')

    # 任务管理
    parser.add_argument('--list-tasks', action='store_true', help='列出所有扫描任务')
    parser.add_argument('--task-stats', action='store_true', help='显示任务统计信息')
    parser.add_argument('--resume', action='store_true', help='恢复中断的扫描任务')

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


def run_single_scan(args, target_url: str, task_manager=None):
    """
    执行单个目标的扫描

    Args:
        args: 命令行参数
        target_url: 扫描目标URL
        task_manager: 任务管理器实例（可选）
    """
    from core.utils.logger import Logger
    from core.scanner import EnhancedWebScanner

    logger = Logger(verbose=args.verbose)

    cookies = parse_cookie(args.cookie)
    headers = parse_headers(args.header)

    if args.auth_token:
        headers['Authorization'] = f"Bearer {args.auth_token}"

    proxy = None
    if args.proxy:
        proxy = {'http': args.proxy, 'https': args.proxy}

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

    ai_config = None
    if args.enable_ai or args.ai_api_key:
        ai_config = {
            'api_key': args.ai_api_key or '',
            'api_base': args.ai_api_base or 'https://api.openai.com/v1',
            'model': args.ai_model or 'gpt-4o-mini',
        }

    task_id = None
    if task_manager:
        task_id = task_manager.create_task(target_url)
        task_manager.update_task_status(task_id, 'running')

    try:
        scanner = EnhancedWebScanner(
            target=target_url,
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
            auth_config=auth_config,
            enable_dedup=not args.no_dedup,
            enable_verification=not args.no_verify,
            enable_ai=args.enable_ai or bool(args.ai_api_key),
            ai_config=ai_config,
            task_id=task_id,
        )

        if not args.quiet:
            logger.info("开始扫描...")

        scanner.scan()

        report_path = scanner.generate_report(format=args.report_format)

        if task_manager and task_id:
            task_manager.save_task_result(task_id, scanner.results)
            task_manager.update_task_report_path(task_id, report_path)

        if args.quiet:
            print(report_path)
        else:
            logger.info(f"扫描完成! 报告已生成: {report_path}")

    except KeyboardInterrupt:
        logger.warning("\n扫描被用户中断")
        if task_manager and task_id:
            task_manager.update_task_status(task_id, 'cancelled')
        sys.exit(130)
    except Exception as e:
        logger.error(f"扫描过程中发生错误: {str(e)}")
        if task_manager and task_id:
            task_manager.update_task_status(task_id, 'failed', error_message=str(e))
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def main():
    """主函数"""
    args = parse_args()

    from core.utils.logger import Logger
    from core.task_manager import TaskManager

    logger = Logger(verbose=args.verbose)

    if args.quiet:
        import logging
        logger.logger.setLevel(logging.WARNING)

    # 列出所有可用插件
    if args.list_plugins:
        from core.plugin_manager import PluginManager
        plugin_dir = args.plugin_dir or 'plugins'
        pm = PluginManager(plugin_dir)
        pm.load_all_plugins()
        plugins = pm.get_all_plugins()
        if not plugins:
            print(f"未在 {plugin_dir} 目录中找到可用插件")
        else:
            print(f"可用插件 (共 {len(plugins)} 个):")
            print("-" * 60)
            for name, cls in plugins.items():
                doc = (cls.__doc__ or '').strip().split('\n')[0]
                print(f"  {name:<30} {doc}")
        return

    task_manager = TaskManager()

    # 任务管理命令
    if args.list_tasks:
        tasks = task_manager.list_tasks()
        if not tasks:
            logger.info("暂无扫描任务")
            return
        print(f"{'任务ID':<30} {'目标URL':<40} {'状态':<10} {'漏洞数':<8} {'创建时间':<20}")
        print("-" * 110)
        for task in tasks:
            print(
                f"{task['task_id']:<30} "
                f"{task['target_url'][:38]:<40} "
                f"{task['status']:<10} "
                f"{task['vuln_count']:<8} "
                f"{task['created_at']:<20}"
            )
        return

    if args.task_stats:
        stats = task_manager.get_statistics()
        print("=== 任务统计 ===")
        print(f"任务状态分布: {stats['tasks']}")
        print(f"漏洞总数: {stats['total_vulnerabilities']}")
        print(f"漏洞严重程度分布: {stats['vulnerabilities_by_severity']}")
        return

    # 恢复中断任务
    if args.resume:
        interrupted = task_manager.get_interrupted_tasks()
        if not interrupted:
            logger.info("没有可恢复的中断任务")
            return
        print(f"发现 {len(interrupted)} 个可恢复任务:")
        for task in interrupted:
            print(f"  - {task['task_id']}: {task['target_url']} ({task['status']})")
        for task in interrupted:
            task_manager.update_task_status(task['task_id'], 'pending')
            run_single_scan(args, task['target_url'], task_manager)
        return

    # 检查目标参数
    if not args.target and not args.targets:
        logger.warning("错误: 请指定扫描目标 (--target 或 --targets)")
        sys.exit(1)

    # 显示扫描配置
    if not args.quiet and args.target:
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
        logger.info(f"全局去重: {'禁用' if args.no_dedup else '启用'}")
        logger.info(f"二次验证: {'禁用' if args.no_verify else '启用'}")
        logger.info(f"AI分析: {'启用' if args.enable_ai or args.ai_api_key else '禁用'}")
        logger.info("=" * 70)

    # 单目标扫描
    if args.target:
        run_single_scan(args, args.target, task_manager)

    # 多目标批量扫描
    elif args.targets:
        if not os.path.exists(args.targets):
            logger.warning(f"错误: 目标文件不存在: {args.targets}")
            sys.exit(1)

        task_ids = task_manager.load_targets_from_file(args.targets)
        if not task_ids:
            logger.warning("错误: 未找到有效的目标URL")
            sys.exit(1)

        logger.info(f"批量扫描: 共 {len(task_ids)} 个目标")

        pending_tasks = task_manager.get_pending_tasks(limit=len(task_ids))
        for idx, task in enumerate(pending_tasks, 1):
            logger.info(f"\n{'=' * 70}")
            logger.info(f"扫描目标 [{idx}/{len(pending_tasks)}]: {task['target_url']}")
            logger.info(f"{'=' * 70}")
            run_single_scan(args, task['target_url'], task_manager)

        stats = task_manager.get_statistics()
        logger.info(f"\n批量扫描完成! 任务统计: {stats['tasks']}")


if __name__ == '__main__':
    main()
