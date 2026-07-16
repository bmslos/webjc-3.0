# -*- coding: utf-8 -*-
"""报告生成器 XSS 转义单元测试"""

import pytest
from core.utils.report import _esc


class TestEscFunction:
    """_esc HTML转义函数测试"""

    def test_esc_script_tag(self):
        """测试转义 <script> 标签"""
        result = _esc('<script>alert(1)</script>')
        assert '<script>' not in result
        assert '&lt;script&gt;' in result

    def test_esc_quotes(self):
        """测试转义引号"""
        result = _esc('" onclick="alert(1)')
        assert '"' not in result
        assert '&quot;' in result

    def test_esc_single_quote(self):
        """测试转义单引号"""
        result = _esc("javascript:alert('xss')")
        assert '&#x27;' in result or "'" not in result

    def test_esc_ampersand(self):
        """测试转义 & 符号"""
        result = _esc('a&b')
        assert '&amp;' in result

    def test_esc_normal_text_unchanged(self):
        """测试正常文本不被修改"""
        assert _esc('正常文本') == '正常文本'
        assert _esc('http://example.com/page?id=1') == 'http://example.com/page?id=1'

    def test_esc_empty_string(self):
        """测试空字符串"""
        assert _esc('') == ''

    def test_esc_none_value(self):
        """测试 None 值"""
        assert _esc(None) == 'None'

    def test_esc_integer(self):
        """测试整数值被转为字符串"""
        assert _esc(42) == '42'

    def test_esc_complex_xss_payload(self, xss_payloads):
        """测试复杂 XSS payload 转义"""
        for payload in xss_payloads:
            result = _esc(payload)
            # 转义后不应包含可执行的 HTML 标签（<> 被转义）
            assert '<script' not in result.lower()
            assert '<img' not in result.lower()
            assert '<svg' not in result.lower()
            # 原始的尖括号必须被转义为 &lt; / &gt;
            assert '<' not in result or '&lt;' in result
            assert '>' not in result or '&gt;' in result

    def test_esc_prevents_attribute_injection(self):
        """测试防止属性注入"""
        payload = '" onmouseover="alert(1)'
        result = _esc(payload)
        assert 'onmouseover' not in result or '"' not in result.split('onmouseover')[0]
