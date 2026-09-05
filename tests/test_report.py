# -*- coding: utf-8 -*-
"""报告生成器单元测试：HTML 转义（Jinja2 autoescape 实际渲染路径）与 CSV 注入防护"""

import csv
from core.utils.report import ReportGenerator


def _make_results(payload):
    """构造包含指定payload的扫描结果"""
    return {
        'target': 'http://example.com/?q=' + payload,
        'scan_time': '2026-09-03 00:00:00',
        'vulnerabilities': [{
            'type': 'XSS(反射型)',
            'severity': '高危',
            'url': 'http://example.com/page?q=' + payload,
            'parameter': 'q',
            'method': 'GET',
            'payload': payload,
            'description': '参数 q 存在XSS漏洞 ' + payload,
            'recommendation': '对用户输入进行HTML编码',
        }],
        'scan_stats': {},
    }


class TestHtmlEscaping:
    """HTML 报告转义测试（验证 Jinja2 autoescape 实际输出）"""

    def test_html_report_escapes_script_tag(self, tmp_path):
        """测试 <script> 标签被转义"""
        gen = ReportGenerator(str(tmp_path))
        html = gen._generate_html_report(_make_results('<script>alert(1)</script>'))
        assert '<script>alert(1)</script>' not in html
        assert '&lt;script&gt;' in html

    def test_html_report_escapes_quotes(self, tmp_path):
        """测试引号被转义（Jinja2/MarkupSafe 将双引号转义为 &#34;）"""
        gen = ReportGenerator(str(tmp_path))
        html = gen._generate_html_report(_make_results('" onclick="alert(1)'))
        assert '" onclick=' not in html
        assert '&#34;' in html

    def test_html_report_escapes_ampersand(self, tmp_path):
        """测试 & 符号被转义"""
        gen = ReportGenerator(str(tmp_path))
        html = gen._generate_html_report(_make_results('a&b'))
        assert '&amp;' in html

    def test_html_report_normal_text_unchanged(self, tmp_path):
        """测试正常文本不被修改"""
        gen = ReportGenerator(str(tmp_path))
        html = gen._generate_html_report(_make_results('normal_param'))
        assert 'normal_param' in html

    def test_html_report_escapes_target_url(self, tmp_path):
        """测试target字段（页面标题）同样被转义"""
        gen = ReportGenerator(str(tmp_path))
        html = gen._generate_html_report(_make_results('<script>alert(1)</script>'))
        # 标题中不允许出现未转义的payload
        assert '<script>alert(1)</script>' not in html
        assert '<title>' in html

    def test_html_report_escapes_complex_xss_payloads(self, tmp_path, xss_payloads):
        """测试复杂 XSS payload 转义：含HTML特殊字符的payload不得原样出现"""
        gen = ReportGenerator(str(tmp_path))
        for payload in xss_payloads:
            html = gen._generate_html_report(_make_results(payload))
            # 含HTML特殊字符的payload会被转义，不得原样出现在输出中
            if any(ch in payload for ch in '<>&"\''):
                assert payload not in html, f"payload 未被转义: {payload}"
            # 可执行标签构造不得出现在任何输出中
            assert '<script' not in html.lower()
            assert '<img' not in html.lower()
            assert '<svg' not in html.lower()

    def test_html_report_empty_vulnerabilities(self, tmp_path):
        """测试无漏洞时的渲染"""
        gen = ReportGenerator(str(tmp_path))
        results = {'target': 'http://example.com', 'scan_time': '', 'vulnerabilities': [], 'scan_stats': {}}
        html = gen._generate_html_report(results)
        assert '未发现漏洞' in html


class TestCsvSafety:
    """CSV 注入防护测试"""

    def test_csv_injection_formula_escaped(self, tmp_path):
        """测试以=开头的公式payload被前置单引号转义"""
        gen = ReportGenerator(str(tmp_path))
        results = _make_results("=cmd|' /C calc'!A0")
        path = gen.generate_csv(results)

        with open(path, encoding='utf-8-sig', newline='') as f:
            rows = list(csv.reader(f))

        # Payload列（第7列，索引6）应以'开头，防止Excel公式执行
        payload_cell = rows[1][6]
        assert payload_cell.startswith("'=")

    def test_csv_normal_payload_unchanged(self, tmp_path):
        """测试正常payload不被修改"""
        gen = ReportGenerator(str(tmp_path))
        results = _make_results("' OR '1'='1")
        path = gen.generate_csv(results)

        with open(path, encoding='utf-8-sig', newline='') as f:
            rows = list(csv.reader(f))

        payload_cell = rows[1][6]
        assert payload_cell == "' OR '1'='1"
