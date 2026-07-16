#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
报告生成器 - 增强版,支持HTML、JSON、CSV格式
"""

import os
import json
import csv
from html import escape as _html_escape
from typing import Dict, List, Any
from datetime import datetime
from jinja2 import Environment, select_autoescape
from core.utils.logger import Logger


def _esc(value) -> str:
    """HTML转义辅助函数，防止存储型XSS"""
    return _html_escape(str(value), quote=True)


# Jinja2 环境，开启 HTML 自动转义
_jinja_env = Environment(autoescape=select_autoescape(['html', 'xml']))

# HTML 报告模板（Jinja2 autoescape 自动转义所有 {{ }} 变量）
_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web漏洞扫描报告 - {{ target }}</title>
    <style>
        {% raw %}
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #f5f7fa; color: #333; line-height: 1.6; padding: 20px;
        }
        .container {
            max-width: 1200px; margin: 0 auto; background: white;
            border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 40px;
        }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 15px; margin-bottom: 30px; }
        h2 { color: #34495e; margin-top: 30px; margin-bottom: 20px; border-left: 4px solid #3498db; padding-left: 15px; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .info-card { background: #f8f9fa; border-radius: 8px; padding: 20px; border-left: 4px solid #3498db; }
        .info-card label { font-weight: bold; color: #7f8c8d; display: block; margin-bottom: 5px; font-size: 0.9em; }
        .info-card value { color: #2c3e50; font-size: 1.1em; }
        .severity-summary { display: flex; gap: 15px; margin-bottom: 30px; flex-wrap: wrap; }
        .severity-badge { padding: 15px 25px; border-radius: 8px; color: white; font-weight: bold; text-align: center; flex: 1; min-width: 120px; }
        .severity-critical { background: #8e44ad; }
        .severity-high { background: #e74c3c; }
        .severity-medium { background: #f39c12; }
        .severity-low { background: #3498db; }
        .severity-info { background: #95a5a6; }
        .vuln-item { background: #f8f9fa; border-radius: 8px; padding: 20px; margin-bottom: 20px; border-left: 4px solid; }
        .vuln-critical { border-left-color: #8e44ad; }
        .vuln-high { border-left-color: #e74c3c; }
        .vuln-medium { border-left-color: #f39c12; }
        .vuln-low { border-left-color: #3498db; }
        .vuln-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .vuln-type { font-size: 1.2em; font-weight: bold; color: #2c3e50; }
        .vuln-details { margin: 10px 0; }
        .vuln-details label { font-weight: bold; color: #7f8c8d; }
        .vuln-details value { color: #2c3e50; }
        .recommendation { background: #e8f6f3; padding: 15px; border-radius: 5px; margin-top: 15px; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 2px solid #ecf0f1; text-align: center; color: #7f8c8d; }
        {% endraw %}
    </style>
</head>
<body>
    <div class="container">
        <h1>Web应用漏洞扫描报告</h1>

        <div class="info-grid">
            <div class="info-card">
                <label>扫描目标</label>
                <value>{{ target }}</value>
            </div>
            <div class="info-card">
                <label>扫描时间</label>
                <value>{{ scan_time }}</value>
            </div>
            <div class="info-card">
                <label>发现URL数</label>
                <value>{{ urls_discovered }}</value>
            </div>
            <div class="info-card">
                <label>发现表单数</label>
                <value>{{ forms_discovered }}</value>
            </div>
        </div>

        <h2>漏洞概览</h2>
        <div class="severity-summary">
            <div class="severity-badge severity-critical">严重: {{ severity_count['严重'] }}</div>
            <div class="severity-badge severity-high">高危: {{ severity_count['高危'] }}</div>
            <div class="severity-badge severity-medium">中危: {{ severity_count['中危'] }}</div>
            <div class="severity-badge severity-low">低危: {{ severity_count['低危'] }}</div>
            <div class="severity-badge severity-info">信息: {{ severity_count['信息'] }}</div>
            <div class="severity-badge" style="background: #2c3e50;">总计: {{ total_vulns }}</div>
        </div>

        <h2>漏洞详情</h2>
        {% if not vulnerabilities %}
        <div style="text-align: center; padding: 40px; color: #27ae60;">
            <h3>未发现漏洞</h3>
            <p>恭喜! 扫描未发现明显的安全漏洞。</p>
        </div>
        {% else %}
        {% for vuln in vulnerabilities %}
        <div class="vuln-item {{ vuln.severity_class }}">
            <div class="vuln-header">
                <div class="vuln-type">#{{ loop.index }} {{ vuln.type }}</div>
                <div class="severity-badge severity-{{ vuln.severity_lower }}">
                    {{ vuln.severity }}
                </div>
            </div>
            <div class="vuln-details">
                <div><label>URL:</label> <value>{{ vuln.url }}</value></div>
                <div><label>参数:</label> <value>{{ vuln.parameter }}</value></div>
                <div><label>请求方法:</label> <value>{{ vuln.method }}</value></div>
                <div><label>Payload:</label> <value><code>{{ vuln.payload }}</code></value></div>
                <div><label>描述:</label> <value>{{ vuln.description }}</value></div>
            </div>
            <div class="recommendation">
                <label>修复建议:</label>
                <p>{{ vuln.recommendation }}</p>
            </div>
        </div>
        {% endfor %}
        {% endif %}

        <div class="footer">
            <p>本报告由 Web漏洞扫描工具增强版 自动生成</p>
            <p>生成时间: {{ generation_time }}</p>
        </div>
    </div>
</body>
</html>"""


class ReportGenerator:
    """报告生成器"""

    def __init__(self, output_dir: str = 'reports'):
        """
        初始化报告生成器

        Args:
            output_dir: 报告输出目录
        """
        self.output_dir = output_dir
        self.logger = Logger()
        self._template = _jinja_env.from_string(_HTML_TEMPLATE)

    def generate(self, results: Dict[str, Any]) -> str:
        """
        生成HTML格式报告

        Args:
            results: 扫描结果

        Returns:
            报告文件路径
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(self.output_dir, f"scan_report_{timestamp}.html")

        # 生成HTML报告
        html_content = self._generate_html_report(results)

        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        self.logger.info(f"HTML报告已生成: {report_file}")
        return report_file

    def generate_json(self, results: Dict[str, Any]) -> str:
        """
        生成JSON格式报告

        Args:
            results: 扫描结果

        Returns:
            报告文件路径
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(self.output_dir, f"scan_report_{timestamp}.json")

        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        self.logger.info(f"JSON报告已生成: {report_file}")
        return report_file

    def generate_csv(self, results: Dict[str, Any]) -> str:
        """
        生成CSV格式报告

        Args:
            results: 扫描结果

        Returns:
            报告文件路径
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(self.output_dir, f"scan_report_{timestamp}.csv")

        vulnerabilities = results.get('vulnerabilities', [])

        if not vulnerabilities:
            self.logger.warning("没有漏洞数据,无法生成CSV报告")
            return ""

        # CSV字段
        fieldnames = [
            '编号', '漏洞类型', '严重程度', 'URL', '参数', '请求方法',
            'Payload', '描述', '修复建议'
        ]

        with open(report_file, 'w', encoding='utf-8-sig', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

            for idx, vuln in enumerate(vulnerabilities, 1):
                writer.writerow({
                    '编号': idx,
                    '漏洞类型': vuln.get('type', ''),
                    '严重程度': vuln.get('severity', ''),
                    'URL': vuln.get('url', ''),
                    '参数': vuln.get('parameter', ''),
                    '请求方法': vuln.get('method', ''),
                    'Payload': vuln.get('payload', ''),
                    '描述': vuln.get('description', ''),
                    '修复建议': vuln.get('recommendation', '')
                })

        self.logger.info(f"CSV报告已生成: {report_file}")
        return report_file

    def _generate_html_report(self, results: Dict[str, Any]) -> str:
        """
        生成HTML报告内容（Jinja2 模板渲染，autoescape 自动转义防 XSS）

        Args:
            results: 扫描结果

        Returns:
            HTML 字符串
        """
        target = results.get('target', '')
        scan_time = results.get('scan_time', '')
        vulnerabilities = results.get('vulnerabilities', [])
        scan_stats = results.get('scan_stats', {})

        # 统计各严重程度数量
        severity_count = {'严重': 0, '高危': 0, '中危': 0, '低危': 0, '信息': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', '信息')
            severity_count[severity] = severity_count.get(severity, 0) + 1

        # 构造漏洞列表上下文（添加 CSS 类名映射）
        vuln_items = self._build_vuln_items(vulnerabilities)

        # 渲染模板（Jinja2 autoescape 自动转义所有变量）
        return self._template.render(
            target=target,
            scan_time=scan_time,
            urls_discovered=scan_stats.get('urls_discovered', 0),
            forms_discovered=scan_stats.get('forms_discovered', 0),
            severity_count=severity_count,
            total_vulns=len(vulnerabilities),
            vulnerabilities=vuln_items,
            generation_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        )

    def _build_vuln_items(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        构造漏洞列表上下文，添加 CSS 类名映射

        Args:
            vulnerabilities: 原始漏洞列表

        Returns:
            带有 severity_class 和 severity_lower 字段的漏洞列表
        """
        severity_class_map = {
            '严重': 'vuln-critical',
            '高危': 'vuln-high',
            '中危': 'vuln-medium',
            '低危': 'vuln-low',
        }
        items = []
        for vuln in vulnerabilities:
            severity = vuln.get('severity', '信息')
            items.append({
                'type': vuln.get('type', '未知'),
                'severity': severity,
                'severity_class': severity_class_map.get(severity, 'vuln-low'),
                'severity_lower': severity.lower(),
                'url': vuln.get('url', ''),
                'parameter': vuln.get('parameter', '无'),
                'method': vuln.get('method', 'GET'),
                'payload': vuln.get('payload', ''),
                'description': vuln.get('description', ''),
                'recommendation': vuln.get('recommendation', ''),
            })
        return items
