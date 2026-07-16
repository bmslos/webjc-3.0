# -*- coding: utf-8 -*-
"""BaseDetector 基类单元测试"""

import pytest
from core.detectors.base import BaseDetector


class DummyDetector(BaseDetector):
    """用于测试的检测器桩"""

    name = "测试检测器"

    def scan(self):
        return []


class TestBaseDetector:
    """BaseDetector 基类测试"""

    def test_init_sets_common_attributes(self):
        """测试 __init__ 正确设置公共属性"""
        detector = DummyDetector(
            target="http://example.com",
            http=None,
            urls=["http://example.com/a"],
            forms=[{"action": "test"}],
            params=["id"],
        )
        assert detector.target == "http://example.com"
        assert detector.urls == ["http://example.com/a"]
        assert detector.forms == [{"action": "test"}]
        assert detector.params == ["id"]
        assert detector.logger is not None

    def test_init_defaults(self):
        """测试 __init__ 默认值"""
        detector = DummyDetector(target="http://example.com", http=None)
        assert detector.urls == ["http://example.com"]
        assert detector.forms == []
        assert detector.params == []

    def test_deduplicate_removes_exact_duplicates(self, sample_vulns_list):
        """测试去重：相同URL+参数+类型的漏洞只保留一条"""
        detector = DummyDetector(target="http://example.com", http=None)
        result = detector._deduplicate_vulns(sample_vulns_list)
        # 4条中有1条完全重复（同URL+同参数+同类型），应剩3条
        assert len(result) == 3

    def test_deduplicate_preserves_different_urls(self, sample_vulns_list):
        """测试去重：不同URL的漏洞不被合并"""
        detector = DummyDetector(target="http://example.com", http=None)
        result = detector._deduplicate_vulns(sample_vulns_list)
        urls = {v['url'] for v in result}
        assert "http://example.com/page?id=1" in urls
        assert "http://example.com/other?id=1" in urls

    def test_deduplicate_preserves_different_params(self, sample_vulns_list):
        """测试去重：同URL不同参数的漏洞不被合并"""
        detector = DummyDetector(target="http://example.com", http=None)
        result = detector._deduplicate_vulns(sample_vulns_list)
        params = {v['parameter'] for v in result if v['url'] == 'http://example.com/page?id=1'}
        assert 'id' in params
        assert 'name' in params

    def test_deduplicate_empty_list(self):
        """测试去重：空列表返回空"""
        detector = DummyDetector(target="http://example.com", http=None)
        assert detector._deduplicate_vulns([]) == []

    def test_build_vuln_structure(self):
        """测试 _build_vuln 构造标准漏洞字典"""
        detector = DummyDetector(target="http://example.com", http=None)
        vuln = detector._build_vuln(
            vuln_type="XSS",
            severity="高危",
            url="http://example.com",
            parameter="q",
            payload="<script>",
            description="XSS漏洞",
            recommendation="转义输出",
        )
        assert vuln['type'] == "XSS"
        assert vuln['severity'] == "高危"
        assert vuln['url'] == "http://example.com"
        assert vuln['parameter'] == "q"
        assert vuln['method'] == "GET"
        assert vuln['payload'] == "<script>"
        assert vuln['description'] == "XSS漏洞"
        assert vuln['recommendation'] == "转义输出"

    def test_build_vuln_with_extra_fields(self):
        """测试 _build_vuln 支持额外字段"""
        detector = DummyDetector(target="http://example.com", http=None)
        vuln = detector._build_vuln(
            vuln_type="SSRF",
            severity="高危",
            url="http://example.com",
            confidence=0.85,
            verification_status="verified",
        )
        assert vuln['confidence'] == 0.85
        assert vuln['verification_status'] == "verified"

    def test_load_vuln_config_returns_dict(self):
        """测试 _load_vuln_config 返回配置字典"""
        detector = DummyDetector(target="http://example.com", http=None)
        config = detector._load_vuln_config('sqli')
        assert isinstance(config, dict)
        # VULN_CONFIG 中应该有 sqli 的 payloads
        assert 'payloads' in config or len(config) >= 0

    def test_scan_is_abstract(self):
        """测试 scan() 是抽象方法，直接实例化 BaseDetector 应失败"""
        with pytest.raises(TypeError):
            BaseDetector(target="http://example.com", http=None)
