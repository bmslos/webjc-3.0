#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
AI分析引擎 - LLM误报过滤与智能payload生成

核心功能:
1. LLM误报过滤 - 调用大模型API分析漏洞上下文，判断是否为误报
2. 智能payload生成 - 根据目标上下文和参数类型动态生成针对性测试用例
3. 修复建议增强 - 利用LLM生成更详细、更具操作性的修复方案
4. 多模型支持 - 兼容OpenAI API、DeepSeek、通义千问等主流大模型

设计原则:
- LLM调用为可选功能，未配置API时自动降级为规则引擎
- 所有LLM调用包含超时和重试机制
- 敏感信息（API Key）通过环境变量注入，不硬编码
"""

import os
import json
import time
from typing import Dict, List, Optional, Any
from core.utils.logger import Logger


class AIAnalyzer:
    """
    AI分析引擎

    集成LLM大模型能力，提供误报过滤和智能payload生成。
    支持OpenAI兼容API接口（OpenAI/DeepSeek/通义千问等）。
    """

    def __init__(self, config: Optional[Dict] = None):
        """
        初始化AI分析引擎

        Args:
            config: AI配置字典，包含 api_key, api_base, model 等参数。
                    未提供时从环境变量读取。
        """
        self.logger = Logger()
        self.config = config or {}
        self.api_key = (
            self.config.get('api_key')
            or os.environ.get('LLM_API_KEY', '')
        )
        self.api_base = (
            self.config.get('api_base')
            or os.environ.get('LLM_API_BASE', 'https://api.openai.com/v1')
        )
        self.model = (
            self.config.get('model')
            or os.environ.get('LLM_MODEL', 'gpt-4o-mini')
        )
        self.max_tokens = self.config.get('max_tokens', 1024)
        self.temperature = self.config.get('temperature', 0.1)
        self.timeout = self.config.get('timeout', 30)
        self.enabled = bool(self.api_key)
        self._client = None

        if self.enabled:
            self.logger.info(f"AI分析引擎已启用, 模型: {self.model}")
        else:
            self.logger.info("AI分析引擎未启用（未配置API Key），将使用规则引擎降级")

    def _get_client(self):
        """
        延迟初始化OpenAI客户端

        首次调用时创建客户端实例，避免模块导入时依赖问题。

        Returns:
            OpenAI客户端实例
        """
        if self._client is not None:
            return self._client

        try:
            from openai import OpenAI
            self._client = OpenAI(
                api_key=self.api_key,
                base_url=self.api_base,
                timeout=self.timeout,
            )
            return self._client
        except ImportError:
            self.logger.error(
                "openai库未安装，请运行: pip install openai"
            )
            self.enabled = False
            return None

    def _call_llm(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """
        调用LLM API

        Args:
            system_prompt: 系统提示词
            user_prompt: 用户提示词

        Returns:
            LLM响应文本，失败返回None
        """
        if not self.enabled:
            return None

        client = self._get_client()
        if not client:
            return None

        try:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            self.logger.error(f"LLM调用失败: {str(e)}")
            return None

    def filter_false_positives(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        LLM误报过滤

        将漏洞上下文信息发送给LLM，由模型判断是否为误报。
        对于LLM判定为误报的漏洞，标记为 rejected 并降低置信度。
        未启用LLM时，使用规则引擎降级过滤。

        Args:
            vulnerabilities: 待过滤的漏洞列表

        Returns:
            过滤后的漏洞列表
        """
        if not vulnerabilities:
            return vulnerabilities

        if not self.enabled:
            return self._rule_based_filter(vulnerabilities)

        self.logger.info(f"LLM误报过滤: 分析 {len(vulnerabilities)} 条漏洞...")
        filtered = []

        for vuln in vulnerabilities:
            try:
                analysis = self._analyze_vuln_with_llm(vuln)
                if analysis:
                    is_false_positive = analysis.get('is_false_positive', False)
                    confidence_adjustment = analysis.get('confidence_adjustment', 0.0)
                    reason = analysis.get('reason', '')

                    if is_false_positive:
                        vuln['verification_status'] = 'rejected_by_ai'
                        vuln['confidence'] = max(0.0, vuln.get('confidence', 0.5) - 0.3)
                        vuln['ai_analysis'] = {
                            'is_false_positive': True,
                            'reason': reason,
                        }
                        self.logger.info(
                            f"AI判定误报: {vuln.get('type', '')} - "
                            f"{vuln.get('url', '')} - 原因: {reason}"
                        )
                    else:
                        vuln['confidence'] = min(
                            1.0, vuln.get('confidence', 0.5) + confidence_adjustment
                        )
                        vuln['ai_analysis'] = {
                            'is_false_positive': False,
                            'reason': reason,
                        }
            except Exception as e:
                self.logger.error(f"AI分析异常: {str(e)}")

            filtered.append(vuln)

        rejected_count = sum(
            1 for v in filtered
            if v.get('ai_analysis', {}).get('is_false_positive', False)
        )
        self.logger.info(
            f"LLM误报过滤完成: 保留 {len(filtered) - rejected_count} 条, "
            f"标记误报 {rejected_count} 条"
        )

        return filtered

    def _analyze_vuln_with_llm(self, vuln: Dict) -> Optional[Dict]:
        """
        使用LLM分析单条漏洞是否为误报

        构造包含漏洞上下文的提示词，让LLM判断漏洞的真实性。

        Args:
            vuln: 漏洞字典

        Returns:
            分析结果字典，包含 is_false_positive, confidence_adjustment, reason
        """
        system_prompt = (
            "你是一位专业的Web安全分析师。你的任务是分析漏洞扫描工具的报告，"
            "判断每条漏洞是否为误报。\n\n"
            "判断标准:\n"
            "1. payload是否与参数类型匹配（如数字型参数不应触发XSS）\n"
            "2. 漏洞描述是否与实际HTTP响应特征一致\n"
            "3. 是否存在常见的误报模式（如通用错误页面包含关键词）\n"
            "4. 验证状态和置信度是否合理\n\n"
            "请以JSON格式回复，包含以下字段:\n"
            "- is_false_positive: 布尔值，是否为误报\n"
            "- confidence_adjustment: 浮点数，置信度调整值(-0.3到+0.2)\n"
            "- reason: 字符串，判断理由的简要说明\n"
        )

        vuln_summary = {
            'type': vuln.get('type', ''),
            'severity': vuln.get('severity', ''),
            'url': vuln.get('url', ''),
            'parameter': vuln.get('parameter', ''),
            'method': vuln.get('method', ''),
            'payload': vuln.get('payload', ''),
            'description': vuln.get('description', ''),
            'verification_status': vuln.get('verification_status', ''),
            'confidence': vuln.get('confidence', 0.0),
            'param_context': vuln.get('param_context', {}),
        }

        user_prompt = (
            f"请分析以下漏洞是否为误报:\n\n"
            f"```json\n{json.dumps(vuln_summary, ensure_ascii=False, indent=2)}\n```"
        )

        response_text = self._call_llm(system_prompt, user_prompt)
        if not response_text:
            return None

        try:
            json_str = response_text
            if '```json' in json_str:
                json_str = json_str.split('```json')[1].split('```')[0]
            elif '```' in json_str:
                json_str = json_str.split('```')[1].split('```')[0]

            result = json.loads(json_str.strip())
            return {
                'is_false_positive': bool(result.get('is_false_positive', False)),
                'confidence_adjustment': float(
                    result.get('confidence_adjustment', 0.0)
                ),
                'reason': str(result.get('reason', '')),
            }
        except (json.JSONDecodeError, ValueError) as e:
            self.logger.error(f"LLM响应解析失败: {str(e)}, 原始响应: {response_text[:200]}")
            return None

    def _rule_based_filter(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        基于规则的误报过滤（降级方案）

        当LLM不可用时，使用规则引擎进行基础误报过滤。

        Args:
            vulnerabilities: 待过滤的漏洞列表

        Returns:
            过滤后的漏洞列表
        """
        filtered = []
        for vuln in vulnerabilities:
            if self._is_likely_false_positive(vuln):
                vuln['verification_status'] = 'rejected_by_rule'
                vuln['confidence'] = max(0.0, vuln.get('confidence', 0.5) - 0.2)
                self.logger.info(
                    f"规则引擎判定误报: {vuln.get('type', '')} - "
                    f"{vuln.get('url', '')}"
                )
            filtered.append(vuln)

        return filtered

    def _is_likely_false_positive(self, vuln: Dict) -> bool:
        """
        规则引擎误报判断

        基于启发式规则判断漏洞是否可能为误报。

        Args:
            vuln: 漏洞字典

        Returns:
            是否可能为误报
        """
        param_context = vuln.get('param_context', {})
        param_type = param_context.get('type', '')
        vuln_type = vuln.get('type', '').lower()

        if param_type == 'numeric':
            if 'xss' in vuln_type and 'dom' not in vuln_type:
                return True

        if param_type == 'email':
            if 'sqli' in vuln_type or 'sql' in vuln_type:
                return True

        if param_type == 'boolean':
            if any(t in vuln_type for t in ['sqli', 'xss', 'command', 'traversal']):
                return True

        confidence = vuln.get('confidence', 0.5)
        if confidence < 0.2:
            return True

        return False

    def generate_smart_payloads(self, target_url: str, param_name: str,
                                param_value: str, param_type: str,
                                vuln_category: str) -> List[str]:
        """
        智能payload生成

        根据目标上下文（参数类型、参数值、漏洞类别）动态生成
        针对性测试用例，提高检测精度和覆盖率。

        Args:
            target_url: 目标URL
            param_name: 参数名
            param_value: 参数当前值
            param_type: 参数推断类型
            vuln_category: 目标漏洞类别（sqli/xss/command_injection等）

        Returns:
            生成的payload列表
        """
        if self.enabled:
            return self._llm_generate_payloads(
                target_url, param_name, param_value, param_type, vuln_category
            )
        else:
            return self._rule_generate_payloads(
                param_name, param_value, param_type, vuln_category
            )

    def _llm_generate_payloads(self, target_url: str, param_name: str,
                               param_value: str, param_type: str,
                               vuln_category: str) -> List[str]:
        """
        使用LLM生成智能payload

        构造包含目标上下文的提示词，让LLM生成针对性的测试payload。

        Args:
            target_url: 目标URL
            param_name: 参数名
            param_value: 参数当前值
            param_type: 参数推断类型
            vuln_category: 目标漏洞类别

        Returns:
            LLM生成的payload列表
        """
        system_prompt = (
            "你是一位专业的Web安全测试专家。你的任务是根据目标参数的上下文信息，"
            "生成针对性的安全测试payload。\n\n"
            "要求:\n"
            "1. payload必须针对指定的漏洞类别\n"
            "2. 根据参数类型调整payload格式（数字型参数用数字闭合，字符串型用引号闭合）\n"
            "3. 生成3-5个不同变体的payload\n"
            "4. 包含基础测试和绕过技巧\n"
            "5. 仅用于合法安全测试\n\n"
            "请以JSON数组格式回复，每个元素是一个payload字符串。例如:\n"
            '["payload1", "payload2", "payload3"]\n'
        )

        user_prompt = (
            f"目标信息:\n"
            f"- URL: {target_url}\n"
            f"- 参数名: {param_name}\n"
            f"- 参数当前值: {param_value}\n"
            f"- 参数类型: {param_type}\n"
            f"- 目标漏洞类别: {vuln_category}\n\n"
            f"请生成针对性的测试payload。"
        )

        response_text = self._call_llm(system_prompt, user_prompt)
        if not response_text:
            return self._rule_generate_payloads(
                param_name, param_value, param_type, vuln_category
            )

        try:
            json_str = response_text
            if '```json' in json_str:
                json_str = json_str.split('```json')[1].split('```')[0]
            elif '```' in json_str:
                json_str = json_str.split('```')[1].split('```')[0]

            payloads = json.loads(json_str.strip())
            if isinstance(payloads, list):
                self.logger.info(
                    f"LLM生成 {len(payloads)} 个智能payload "
                    f"({vuln_category}/{param_name})"
                )
                return [str(p) for p in payloads[:10]]
        except (json.JSONDecodeError, ValueError) as e:
            self.logger.error(f"LLM payload响应解析失败: {str(e)}")

        return self._rule_generate_payloads(
            param_name, param_value, param_type, vuln_category
        )

    def _rule_generate_payloads(self, param_name: str, param_value: str,
                                param_type: str, vuln_category: str) -> List[str]:
        """
        基于规则的payload生成（降级方案）

        根据参数类型和漏洞类别，从预定义的payload模板中
        选择和调整合适的测试用例。

        Args:
            param_name: 参数名
            param_value: 参数当前值
            param_type: 参数推断类型
            vuln_category: 目标漏洞类别

        Returns:
            生成的payload列表
        """
        payloads = []

        if vuln_category == 'sqli':
            if param_type == 'numeric':
                payloads = [
                    '1 OR 1=1',
                    '1 AND 1=1',
                    '1 UNION SELECT NULL,NULL,NULL--',
                    '1; WAITFOR DELAY \'0:0:3\'--',
                ]
            else:
                payloads = [
                    "' OR '1'='1",
                    "' AND 1=1--",
                    "' UNION SELECT NULL,NULL,NULL--",
                    "1' AND SLEEP(3)--",
                ]

        elif vuln_category == 'xss':
            if param_type == 'url':
                payloads = [
                    'javascript:alert(1)',
                    'data:text/html,<script>alert(1)</script>',
                ]
            else:
                payloads = [
                    '<script>alert(1)</script>',
                    '"><img src=x onerror=alert(1)>',
                    '<svg/onload=alert(1)>',
                ]

        elif vuln_category == 'command_injection':
            if param_type == 'numeric':
                payloads = [
                    '1; id',
                    '1|id',
                    '1&&id',
                ]
            else:
                payloads = [
                    '; id',
                    '| id',
                    '$(id)',
                    '`id`',
                ]

        elif vuln_category == 'directory_traversal':
            if param_type == 'filepath':
                payloads = [
                    '../../../etc/passwd',
                    '..%2f..%2f..%2fetc%2fpasswd',
                    '....//....//....//etc/passwd',
                ]
            else:
                payloads = [
                    '../../../etc/passwd',
                    '..\\..\\..\\windows\\win.ini',
                ]

        elif vuln_category == 'ssrf':
            payloads = [
                'http://127.0.0.1',
                'http://169.254.169.254/latest/meta-data/',
                'http://[::1]',
            ]

        else:
            payloads = VULN_CONFIG.get(vuln_category, {}).get('payloads', [])

        return payloads

    def enhance_recommendation(self, vuln: Dict) -> str:
        """
        使用LLM增强修复建议

        为漏洞生成更详细、更具操作性的修复方案，
        包含代码示例和最佳实践。

        Args:
            vuln: 漏洞字典

        Returns:
            增强后的修复建议字符串
        """
        if not self.enabled:
            return vuln.get('recommendation', '')

        system_prompt = (
            "你是一位Web安全专家。请为以下漏洞提供详细的修复建议。\n\n"
            "要求:\n"
            "1. 提供具体的代码修复示例\n"
            "2. 说明修复原理\n"
            "3. 给出相关的安全最佳实践\n"
            "4. 用中文回答，简洁专业\n"
        )

        vuln_info = (
            f"漏洞类型: {vuln.get('type', '')}\n"
            f"严重程度: {vuln.get('severity', '')}\n"
            f"参数: {vuln.get('parameter', '')}\n"
            f"Payload: {vuln.get('payload', '')}\n"
            f"描述: {vuln.get('description', '')}\n"
        )

        enhanced = self._call_llm(system_prompt, vuln_info)
        return enhanced if enhanced else vuln.get('recommendation', '')
