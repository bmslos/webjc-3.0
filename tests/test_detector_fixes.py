# -*- coding: utf-8 -*-
"""针对审查修复项的回归测试：检测器逻辑与二次验证"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))


class FakeResponse:
    """模拟HTTP响应"""

    def __init__(self, status_code=200, text=''):
        self.status_code = status_code
        self.text = text
        self.headers = {}


class FakeHttp:
    """模拟HTTP工具：记录所有请求URL，按脚本返回响应"""

    def __init__(self, responses=None):
        # responses: 可调用列表，按请求顺序依次调用；耗尽后返回默认响应
        self.responses = list(responses or [])
        self.requested_urls = []

    def get(self, url, **kwargs):
        self.requested_urls.append(url)
        if self.responses:
            return self.responses.pop(0)
        return FakeResponse(text='x' * 100)

    def post(self, url, **kwargs):
        return FakeResponse(text='')


class TestBooleanSqli:
    """SQL布尔盲注修复回归测试"""

    def _make_detector(self, http):
        from core.detectors.sqli import SQLInjectionDetector
        return SQLInjectionDetector(
            target='http://example.com',
            http=http,
            urls=['http://example.com/page?id=5&name=x'],
        )

    def test_boolean_sqli_builds_valid_urls(self):
        """测试URL构造：不得出现?id=5?id=1这类畸形拼接"""
        http = FakeHttp()
        detector = self._make_detector(http)
        detector._test_boolean_based('http://example.com/page?id=5&name=x')

        assert http.requested_urls, "应发出验证请求"
        for url in http.requested_urls:
            assert url.count('?') == 1, f"URL包含多个问号（畸形拼接）: {url}"
            assert url.startswith('http://example.com/page?'), f"URL基础部分错误: {url}"

    def test_boolean_sqli_param_encoded(self):
        """测试payload被正确URL编码（含空格/引号的payload）"""
        http = FakeHttp()
        detector = self._make_detector(http)
        detector._test_boolean_based('http://example.com/page?id=5')

        # 含空格的payload不应原样出现在URL中
        for url in http.requested_urls:
            assert ' ' not in url, f"payload未URL编码: {url}"

    def test_boolean_sqli_detects_response_difference(self):
        """测试布尔差异检测：TRUE/FALSE响应差异明显时报漏洞"""
        # 请求顺序：normal(100), true(100), false(300)
        http = FakeHttp(responses=[
            FakeResponse(text='a' * 100),
            FakeResponse(text='a' * 100),
            FakeResponse(text='a' * 300),
        ])
        detector = self._make_detector(http)
        vulns = detector._test_boolean_based('http://example.com/page?id=5')

        assert len(vulns) == 1, f"应检出1个布尔盲注漏洞: {len(vulns)}"
        assert vulns[0]['type'] == 'SQL注入(布尔盲注)'
        assert vulns[0]['parameter'] == 'id'


class TestVerificationFailure:
    """二次验证修复回归测试：验证请求全部失败时不得判定为rejected"""

    def _make_vuln(self, vuln_type):
        return {
            'type': vuln_type,
            'severity': '高危',
            'url': 'http://example.com/page?id=1',
            'parameter': 'id',
            'method': 'GET',
            'payload': "' OR '1'='1",
        }

    def test_all_requests_failed_is_inconclusive_error_based(self):
        """错误回显验证：请求全部失败应为inconclusive而非rejected"""
        from core.verification import VerificationEngine

        class FailingHttp:
            def get(self, url, **kwargs):
                return None

        engine = VerificationEngine(FailingHttp())
        vuln = self._make_vuln('SQL注入(错误回显)')
        engine.verify_vulnerability(vuln)

        assert vuln['verification_status'] == 'inconclusive', \
            f"验证请求全部失败不应判定为rejected: {vuln['verification_status']}"

    def test_all_requests_failed_is_inconclusive_time_based(self):
        """时间盲注验证：请求全部失败应为inconclusive而非rejected"""
        from core.verification import VerificationEngine

        class FailingHttp:
            def get(self, url, **kwargs):
                return None

        engine = VerificationEngine(FailingHttp())
        vuln = self._make_vuln('SQL注入(时间盲注)')
        engine.verify_vulnerability(vuln)

        assert vuln['verification_status'] == 'inconclusive', \
            f"验证请求全部失败不应判定为rejected: {vuln['verification_status']}"

    def test_no_evidence_with_successful_requests_is_rejected(self):
        """错误回显验证：请求成功但无错误特征时应为rejected（保护反向逻辑）"""
        from core.verification import VerificationEngine

        http = FakeHttp()  # 返回200且无SQL错误特征
        engine = VerificationEngine(http)
        vuln = self._make_vuln('SQL注入(错误回显)')
        engine.verify_vulnerability(vuln)

        assert vuln['verification_status'] == 'rejected'


class TestXssReflection:
    """XSS反射判断修复回归测试"""

    def _make_detector(self):
        from core.detectors.xss import XSSDetector
        return XSSDetector(target='http://example.com', http=None)

    def test_page_own_script_tag_not_triggered(self):
        """页面自身含<script>标签不应触发反射判定（误报修复）"""
        detector = self._make_detector()
        payload = '<script>alert("XSS")</script>'
        page = '<html><body><script src="app.js"></script>normal content</body></html>'
        assert detector._check_reflection(page, payload) is False

    def test_page_own_svg_tag_not_triggered(self):
        """页面自身含<svg>标签不应触发反射判定"""
        detector = self._make_detector()
        payload = '<svg onload=alert("XSS")>'
        page = '<html><body><svg width="10"><circle r="5"/></svg></body></html>'
        assert detector._check_reflection(page, payload) is False

    def test_full_payload_reflection_detected(self):
        """payload完整反射时应检出"""
        detector = self._make_detector()
        payload = '<script>alert("XSS")</script>'
        page = f'<html><body>search: {payload}</body></html>'
        assert detector._check_reflection(page, payload) is True

    def test_alert_marker_reflection_detected(self):
        """payload核心特征（alert调用）反射时应检出"""
        detector = self._make_detector()
        payload = '<img src=x onerror=alert("XSS")>'
        page = '<html><body>value: <img src=x onerror=alert("XSS") ></body></html>'
        assert detector._check_reflection(page, payload) is True


class TestSensitiveFiles:
    """敏感文件软404判断修复回归测试"""

    def _make_detector(self):
        from core.detectors.sensitive_files import SensitiveFilesDetector
        return SensitiveFilesDetector(target='http://example.com', http=None)

    def test_soft_404_page_rejected(self):
        """返回200但内容为404页面的响应应判为无效（软404修复）"""
        detector = self._make_detector()
        response = FakeResponse(
            status_code=200,
            text='<html><body><h1>404 Not Found</h1><p>The page you requested was not found.</p></body></html>',
        )
        assert detector._is_valid_content(response) is False

    def test_valid_content_accepted(self):
        """正常配置文件内容应判为有效"""
        detector = self._make_detector()
        response = FakeResponse(
            status_code=200,
            text='DB_HOST=localhost\nDB_PASSWORD=secret123\nAPI_KEY=abcdef123456',
        )
        assert detector._is_valid_content(response) is True


if __name__ == '__main__':
    print("=" * 60)
    print("审查修复项回归测试")
    print("=" * 60)

    TestBooleanSqli().test_boolean_sqli_builds_valid_urls()
    TestBooleanSqli().test_boolean_sqli_param_encoded()
    TestBooleanSqli().test_boolean_sqli_detects_response_difference()
    TestVerificationFailure().test_all_requests_failed_is_inconclusive_error_based()
    TestVerificationFailure().test_all_requests_failed_is_inconclusive_time_based()
    TestVerificationFailure().test_no_evidence_with_successful_requests_is_rejected()
    TestXssReflection().test_page_own_script_tag_not_triggered()
    TestXssReflection().test_page_own_svg_tag_not_triggered()
    TestXssReflection().test_full_payload_reflection_detected()
    TestXssReflection().test_alert_marker_reflection_detected()
    TestSensitiveFiles().test_soft_404_page_rejected()
    TestSensitiveFiles().test_valid_content_accepted()

    print()
    print("=" * 60)
    print("所有测试通过!")
    print("=" * 60)
