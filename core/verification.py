#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
二次验证与上下文理解模块

核心功能:
1. 参数类型推断 - 根据参数名、值、上下文推断参数类型（数字/字符串/文件路径/URL等）
2. 二次验证引擎 - 对可疑漏洞使用不同payload重新确认
3. 上下文感知验证 - 根据参数类型和页面上下文调整验证策略
4. 验证置信度评分 - 为每个漏洞计算置信度分数
"""

import re
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.config import VULN_CONFIG
from core.utils.logger import Logger


class ParameterContext:
    """
    参数上下文分析器

    通过分析参数名称、参数值、表单上下文等信息，
    推断参数的可能类型，从而选择更精准的测试payload。
    """

    PARAM_TYPE_NUMERIC = 'numeric'
    PARAM_TYPE_STRING = 'string'
    PARAM_TYPE_FILEPATH = 'filepath'
    PARAM_TYPE_URL = 'url'
    PARAM_TYPE_EMAIL = 'email'
    PARAM_TYPE_BOOLEAN = 'boolean'
    PARAM_TYPE_COMMAND = 'command'
    PARAM_TYPE_XML = 'xml'
    PARAM_TYPE_UNKNOWN = 'unknown'

    PARAM_NAME_HINTS = {
        PARAM_TYPE_NUMERIC: [
            'id', 'uid', 'pid', 'cid', 'page', 'offset', 'limit', 'count',
            'num', 'size', 'index', 'seq', 'order', 'sort', 'rank', 'level',
            'age', 'year', 'month', 'day', 'hour', 'minute', 'second',
            'price', 'amount', 'quantity', 'total', 'sum', 'avg',
        ],
        PARAM_TYPE_FILEPATH: [
            'file', 'path', 'dir', 'folder', 'directory', 'src', 'source',
            'dest', 'destination', 'output', 'input', 'template', 'include',
            'load', 'import', 'require', 'document', 'attachment', 'upload',
        ],
        PARAM_TYPE_URL: [
            'url', 'link', 'href', 'redirect', 'return', 'next', 'goto',
            'target', 'ref', 'referer', 'callback', 'forward', 'site',
            'domain', 'host', 'origin', 'location', 'navigate',
        ],
        PARAM_TYPE_EMAIL: [
            'email', 'mail', 'recipient', 'sender', 'to', 'from', 'cc',
            'bcc', 'address', 'contact',
        ],
        PARAM_TYPE_BOOLEAN: [
            'enabled', 'disabled', 'active', 'visible', 'hidden', 'debug',
            'test', 'admin', 'verified', 'published', 'deleted', 'flag',
        ],
        PARAM_TYPE_COMMAND: [
            'cmd', 'command', 'exec', 'execute', 'run', 'shell', 'system',
            'ping', 'trace', 'lookup', 'query', 'action', 'do', 'op',
        ],
        PARAM_TYPE_XML: [
            'xml', 'soap', 'data', 'payload', 'body', 'content', 'message',
            'request', 'response', 'feed', 'rss', 'atom',
        ],
    }

    @classmethod
    def infer_type(cls, param_name: str, param_value: str = '',
                   form_context: Optional[Dict] = None) -> str:
        """
        推断参数类型

        综合参数名称提示、参数值格式和表单上下文推断参数类型，
        用于指导payload选择和验证策略。

        Args:
            param_name: 参数名称
            param_value: 参数当前值（可选）
            form_context: 表单上下文信息（可选），包含 input type 等

        Returns:
            推断的参数类型字符串
        """
        param_lower = param_name.lower().replace('_', '').replace('-', '')

        if form_context:
            input_type = form_context.get('type', '').lower()
            if input_type in ('number', 'range'):
                return cls.PARAM_TYPE_NUMERIC
            if input_type == 'email':
                return cls.PARAM_TYPE_EMAIL
            if input_type == 'url':
                return cls.PARAM_TYPE_URL
            if input_type in ('checkbox', 'radio'):
                return cls.PARAM_TYPE_BOOLEAN
            if input_type == 'file':
                return cls.PARAM_TYPE_FILEPATH

        for param_type, hints in cls.PARAM_NAME_HINTS.items():
            for hint in hints:
                if hint in param_lower:
                    return param_type

        if param_value:
            if re.match(r'^\d+$', param_value):
                return cls.PARAM_TYPE_NUMERIC
            if re.match(r'^[\w.+-]+@[\w-]+\.[\w.]+$', param_value):
                return cls.PARAM_TYPE_EMAIL
            if re.match(r'^https?://', param_value):
                return cls.PARAM_TYPE_URL
            if re.match(r'^[/\\]', param_value) or '..' in param_value:
                return cls.PARAM_TYPE_FILEPATH

        return cls.PARAM_TYPE_UNKNOWN


class VerificationEngine:
    """
    二次验证引擎

    对检测器发现的可疑漏洞进行二次验证，降低误报率。
    验证策略根据参数类型和漏洞类型动态调整。

    验证方式:
    - SQL注入: 使用不同payload重新触发，确认注入点存在
    - XSS: 使用编码变体验证反射，确认未被过滤
    - 命令注入: 使用时间延迟payload确认命令执行
    - 目录遍历: 使用不同编码路径确认文件读取
    - 通用: 发送无害payload对比基线响应
    """

    VERIFICATION_PAYLOADS = {
        'sqli': {
            'error_reconfirm': [
                "' AND 1=CONVERT(int,(SELECT @@version)) --",
                "' AND 1=CAST((SELECT version()) AS int) --",
                "' UNION SELECT NULL,version(),NULL --",
            ],
            'boolean_reconfirm': [
                ("1' AND 'a'='a", "1' AND 'a'='b"),
                ("1 AND 1=1", "1 AND 1=2"),
            ],
            'time_reconfirm': [
                ("' AND SLEEP(3) --", 3),
                ("'; WAITFOR DELAY '0:0:3' --", 3),
            ],
        },
        'xss': {
            'encoding_variants': [
                '<script>alert(String.fromCharCode(88,83,83))</script>',
                '<img src=x onerror=alert(document.domain)>',
                '<svg/onload=alert(1)>',
                '"><script>alert(1)</script>',
            ],
        },
        'command_injection': {
            'time_reconfirm': [
                ('; sleep 3', 3),
                ('| sleep 3', 3),
                ('& timeout 3', 3),
            ],
        },
        'directory_traversal': {
            'encoding_variants': [
                '../../../etc/passwd',
                '..%2f..%2f..%2fetc%2fpasswd',
                '....//....//....//etc/passwd',
            ],
        },
    }

    def __init__(self, http_utils):
        """
        初始化验证引擎

        Args:
            http_utils: HTTP工具实例，用于发送验证请求
        """
        self.http = http_utils
        self.logger = Logger()
        self.verification_results = {
            'total_verified': 0,
            'confirmed': 0,
            'rejected': 0,
            'inconclusive': 0,
        }

    def verify_vulnerability(self, vuln: Dict) -> Dict:
        """
        对单个漏洞执行二次验证

        根据漏洞类型选择对应的验证策略，
        返回带有置信度评分和验证状态的增强漏洞记录。

        Args:
            vuln: 原始漏洞字典

        Returns:
            增强后的漏洞字典，包含 verification_status 和 confidence 字段
        """
        self.verification_results['total_verified'] += 1
        vuln_type = vuln.get('type', '').lower()
        param_name = vuln.get('parameter', '')
        url = vuln.get('url', '')
        param_value = self._get_original_param_value(url, param_name)

        param_type = ParameterContext.infer_type(param_name, param_value)
        vuln['param_context'] = {
            'type': param_type,
            'original_value': param_value,
        }

        if 'sql' in vuln_type or 'sqli' in vuln_type:
            result = self._verify_sqli(vuln)
        elif 'xss' in vuln_type:
            result = self._verify_xss(vuln)
        elif 'command' in vuln_type or '命令' in vuln_type:
            result = self._verify_command_injection(vuln)
        elif 'traversal' in vuln_type or '遍历' in vuln_type:
            result = self._verify_directory_traversal(vuln)
        else:
            result = self._verify_generic(vuln)

        status = result.get('status', 'inconclusive')
        self.verification_results[status] = self.verification_results.get(status, 0) + 1

        vuln['verification_status'] = status
        vuln['confidence'] = result.get('confidence', 0.5)
        vuln['verification_detail'] = result.get('detail', '')

        return vuln

    def verify_batch(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        批量验证漏洞列表

        Args:
            vulnerabilities: 待验证的漏洞列表

        Returns:
            验证后的漏洞列表，每条记录包含验证状态和置信度
        """
        verified = []
        self.logger.info(f"开始二次验证 {len(vulnerabilities)} 条漏洞...")

        for idx, vuln in enumerate(vulnerabilities, 1):
            self.logger.info(
                f"[{idx}/{len(vulnerabilities)}] 验证: "
                f"{vuln.get('type', '')} - {vuln.get('url', '')}"
            )
            try:
                verified_vuln = self.verify_vulnerability(vuln)
                verified.append(verified_vuln)
            except Exception as e:
                self.logger.error(f"验证失败: {str(e)}")
                vuln['verification_status'] = 'error'
                vuln['confidence'] = 0.0
                vuln['verification_detail'] = f"验证过程异常: {str(e)}"
                verified.append(vuln)

        confirmed_count = sum(
            1 for v in verified if v.get('verification_status') == 'confirmed'
        )
        rejected_count = sum(
            1 for v in verified if v.get('verification_status') == 'rejected'
        )
        self.logger.info(
            f"二次验证完成: 确认 {confirmed_count} 条, "
            f"拒绝 {rejected_count} 条, "
            f"待定 {len(verified) - confirmed_count - rejected_count} 条"
        )

        return verified

    def _get_original_param_value(self, url: str, param_name: str) -> str:
        """
        从URL中提取参数的原始值

        Args:
            url: 完整URL
            param_name: 参数名

        Returns:
            参数原始值字符串
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            values = params.get(param_name, [])
            return values[0] if values else ''
        except Exception:
            return ''

    def _get_baseline_response(self, url: str, param_name: str) -> Optional[object]:
        """
        获取基线响应（使用原始/无害参数值）

        用于与注入payload的响应进行对比，判断是否存在异常差异。

        Args:
            url: 目标URL
            param_name: 参数名

        Returns:
            基线Response对象，失败返回None
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            if param_name in params:
                original_value = params[param_name][0]
            else:
                original_value = '1'

            safe_params = params.copy()
            safe_params[param_name] = [original_value]
            new_query = urlencode(safe_params, doseq=True)
            baseline_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            return self.http.get(baseline_url)
        except Exception:
            return None

    def _verify_sqli(self, vuln: Dict) -> Dict:
        """
        SQL注入二次验证

        使用不同的SQL payload重新测试，确认注入点确实存在。
        根据原始漏洞子类型（错误回显/布尔盲注/时间盲注）选择验证策略。

        Args:
            vuln: SQL注入漏洞字典

        Returns:
            验证结果字典，包含 status, confidence, detail
        """
        url = vuln.get('url', '')
        param = vuln.get('parameter', '')
        vuln_type = vuln.get('type', '').lower()
        payloads_config = self.VERIFICATION_PAYLOADS.get('sqli', {})

        if '错误' in vuln_type or 'error' in vuln_type:
            return self._verify_sqli_error(url, param, payloads_config)
        elif '布尔' in vuln_type or 'boolean' in vuln_type:
            return self._verify_sqli_boolean(url, param, payloads_config)
        elif '时间' in vuln_type or 'time' in vuln_type:
            return self._verify_sqli_time(url, param, payloads_config)
        else:
            return self._verify_sqli_error(url, param, payloads_config)

    def _verify_sqli_error(self, url: str, param: str,
                           payloads_config: Dict) -> Dict:
        """
        SQL注入错误回显验证

        使用不同的错误触发payload确认数据库错误信息可被回显。

        Args:
            url: 目标URL
            param: 参数名
            payloads_config: 验证payload配置

        Returns:
            验证结果字典
        """
        error_payloads = payloads_config.get('error_reconfirm', [])
        error_patterns = VULN_CONFIG.get('sqli', {}).get('error_patterns', [])
        confirm_count = 0

        for payload in error_payloads[:2]:
            test_url = self._build_test_url(url, param, payload)
            response = self.http.get(test_url)

            if response and response.status_code == 200:
                text_lower = response.text.lower()
                for pattern in error_patterns:
                    if pattern.lower() in text_lower:
                        confirm_count += 1
                        break

        if confirm_count >= 1:
            return {
                'status': 'confirmed',
                'confidence': min(0.7 + confirm_count * 0.1, 0.95),
                'detail': f'二次验证确认: {confirm_count} 个不同payload触发数据库错误',
            }
        else:
            return {
                'status': 'rejected',
                'confidence': 0.3,
                'detail': '二次验证未触发数据库错误，可能为误报',
            }

    def _verify_sqli_boolean(self, url: str, param: str,
                             payloads_config: Dict) -> Dict:
        """
        SQL注入布尔盲注验证

        使用不同的布尔条件对确认TRUE/FALSE响应差异。

        Args:
            url: 目标URL
            param: 参数名
            payloads_config: 验证payload配置

        Returns:
            验证结果字典
        """
        boolean_pairs = payloads_config.get('boolean_reconfirm', [])
        confirm_count = 0

        for true_payload, false_payload in boolean_pairs[:2]:
            true_url = self._build_test_url(url, param, true_payload)
            false_url = self._build_test_url(url, param, false_payload)

            true_resp = self.http.get(true_url)
            false_resp = self.http.get(false_url)

            if true_resp and false_resp:
                true_len = len(true_resp.text)
                false_len = len(false_resp.text)
                if abs(true_len - false_len) > max(true_len, false_len) * 0.1:
                    confirm_count += 1

        if confirm_count >= 1:
            return {
                'status': 'confirmed',
                'confidence': 0.75 + confirm_count * 0.1,
                'detail': f'二次验证确认: {confirm_count} 组布尔条件产生不同响应',
            }
        else:
            return {
                'status': 'inconclusive',
                'confidence': 0.4,
                'detail': '二次验证布尔差异不明显，需人工确认',
            }

    def _verify_sqli_time(self, url: str, param: str,
                          payloads_config: Dict) -> Dict:
        """
        SQL注入时间盲注验证

        使用更短的时间延迟（3秒）重新确认响应时间差异。

        Args:
            url: 目标URL
            param: 参数名
            payloads_config: 验证payload配置

        Returns:
            验证结果字典
        """
        time_payloads = payloads_config.get('time_reconfirm', [])
        confirm_count = 0

        for payload, expected_delay in time_payloads[:2]:
            test_url = self._build_test_url(url, param, payload)
            start_time = time.time()
            response = self.http.get(test_url)
            elapsed = time.time() - start_time

            if response and elapsed >= expected_delay * 0.8:
                confirm_count += 1

        if confirm_count >= 1:
            return {
                'status': 'confirmed',
                'confidence': 0.8,
                'detail': f'二次验证确认: {confirm_count} 个时间延迟payload生效',
            }
        else:
            return {
                'status': 'rejected',
                'confidence': 0.25,
                'detail': '二次验证时间延迟未生效，可能为网络波动导致的误报',
            }

    def _verify_xss(self, vuln: Dict) -> Dict:
        """
        XSS二次验证

        使用编码变体和不同标签的payload验证反射，
        确认输入确实未被正确过滤。

        Args:
            vuln: XSS漏洞字典

        Returns:
            验证结果字典
        """
        url = vuln.get('url', '')
        param = vuln.get('parameter', '')
        xss_payloads = self.VERIFICATION_PAYLOADS.get('xss', {}).get(
            'encoding_variants', []
        )
        confirm_count = 0

        for payload in xss_payloads[:3]:
            test_url = self._build_test_url(url, param, payload)
            response = self.http.get(test_url)

            if response and response.status_code == 200:
                xss_markers = ['alert(', 'onerror=', 'onload=', '<script>', '<svg']
                for marker in xss_markers:
                    if marker in payload and marker in response.text:
                        confirm_count += 1
                        break

        if confirm_count >= 1:
            return {
                'status': 'confirmed',
                'confidence': 0.7 + confirm_count * 0.08,
                'detail': f'二次验证确认: {confirm_count} 个编码变体payload被反射',
            }
        else:
            return {
                'status': 'inconclusive',
                'confidence': 0.4,
                'detail': '二次验证未确认XSS反射，可能存在输入过滤',
            }

    def _verify_command_injection(self, vuln: Dict) -> Dict:
        """
        命令注入二次验证

        使用时间延迟payload确认命令执行能力。

        Args:
            vuln: 命令注入漏洞字典

        Returns:
            验证结果字典
        """
        url = vuln.get('url', '')
        param = vuln.get('parameter', '')
        cmd_payloads = self.VERIFICATION_PAYLOADS.get(
            'command_injection', {}
        ).get('time_reconfirm', [])
        confirm_count = 0

        for payload, expected_delay in cmd_payloads[:2]:
            test_url = self._build_test_url(url, param, payload)
            start_time = time.time()
            response = self.http.get(test_url)
            elapsed = time.time() - start_time

            if response and elapsed >= expected_delay * 0.8:
                confirm_count += 1

        if confirm_count >= 1:
            return {
                'status': 'confirmed',
                'confidence': 0.8,
                'detail': f'二次验证确认: {confirm_count} 个时间延迟命令执行成功',
            }
        else:
            return {
                'status': 'inconclusive',
                'confidence': 0.35,
                'detail': '二次验证时间延迟不明显，需人工确认',
            }

    def _verify_directory_traversal(self, vuln: Dict) -> Dict:
        """
        目录遍历二次验证

        使用不同编码的路径确认文件读取能力。

        Args:
            vuln: 目录遍历漏洞字典

        Returns:
            验证结果字典
        """
        url = vuln.get('url', '')
        param = vuln.get('parameter', '')
        traversal_payloads = self.VERIFICATION_PAYLOADS.get(
            'directory_traversal', {}
        ).get('encoding_variants', [])
        file_indicators = ['root:', 'nobody', 'daemon', '[extensions]', '[fonts]']
        confirm_count = 0

        for payload in traversal_payloads[:2]:
            test_url = self._build_test_url(url, param, payload)
            response = self.http.get(test_url)

            if response and response.status_code == 200:
                for indicator in file_indicators:
                    if indicator in response.text.lower():
                        confirm_count += 1
                        break

        if confirm_count >= 1:
            return {
                'status': 'confirmed',
                'confidence': 0.8,
                'detail': f'二次验证确认: {confirm_count} 个编码路径读取到文件内容',
            }
        else:
            return {
                'status': 'inconclusive',
                'confidence': 0.35,
                'detail': '二次验证未确认文件读取，可能存在路径过滤',
            }

    def _verify_generic(self, vuln: Dict) -> Dict:
        """
        通用验证（兜底策略）

        对于没有专门验证策略的漏洞类型，
        通过发送无害payload对比基线响应来判断。

        Args:
            vuln: 通用漏洞字典

        Returns:
            验证结果字典
        """
        url = vuln.get('url', '')
        param = vuln.get('parameter', '')

        baseline = self._get_baseline_response(url, param)
        if not baseline:
            return {
                'status': 'inconclusive',
                'confidence': 0.5,
                'detail': '无法获取基线响应，验证结果不确定',
            }

        safe_payload = 'testvalue123'
        test_url = self._build_test_url(url, param, safe_payload)
        test_resp = self.http.get(test_url)

        if not test_resp:
            return {
                'status': 'inconclusive',
                'confidence': 0.5,
                'detail': '验证请求失败',
            }

        baseline_len = len(baseline.text)
        test_len = len(test_resp.text)
        len_diff_ratio = abs(baseline_len - test_len) / max(baseline_len, 1)

        if len_diff_ratio > 0.3:
            return {
                'status': 'confirmed',
                'confidence': 0.6,
                'detail': f'参数值变化导致响应长度差异 {len_diff_ratio:.1%}，漏洞可能存在',
            }
        else:
            return {
                'status': 'inconclusive',
                'confidence': 0.45,
                'detail': '参数值变化未导致显著响应差异，需人工确认',
            }

    def _build_test_url(self, url: str, param: str, value: str) -> str:
        """
        构建测试URL

        将指定参数替换为给定值，保留其他参数不变。

        Args:
            url: 原始URL
            param: 要替换的参数名
            value: 新的参数值

        Returns:
            构建的测试URL字符串
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [value]
            new_query = urlencode(params, doseq=True)
            return urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
        except Exception:
            return url

    def get_stats(self) -> Dict:
        """
        获取验证统计信息

        Returns:
            包含验证状态计数的统计字典
        """
        return self.verification_results.copy()
