#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
全局交叉去重引擎 - 统一管理所有检测器的漏洞结果，实现跨检测器交叉去重

核心功能:
1. 基于输入点的交叉去重（同一URL+同一参数的不同漏洞类型合并）
2. 基于漏洞指纹的精确去重（URL+参数+漏洞子类型的完整匹配）
3. 基于关联分析的智能合并（同一根因的多个漏洞聚合为一条）
4. 去重统计和报告
"""

import hashlib
from typing import Dict, List, Optional, Tuple, Set
from urllib.parse import urlparse, parse_qs, urlunparse
from core.utils.logger import Logger


class DedupEngine:
    """
    全局交叉去重引擎

    负责对所有检测器产出的漏洞结果进行统一去重处理，
    解决不同检测器对同一输入点报告不同漏洞类型的交叉重复问题。

    去重层级:
    - L1 精确去重: URL + 参数 + 漏洞子类型 完全相同
    - L2 输入点去重: 同一URL同一参数，保留最严重的漏洞类型
    - L3 关联合并: 同一根因（如同一输入点）触发的多个漏洞聚合
    """

    def __init__(self):
        """
        初始化去重引擎

        Attributes:
            logger: 日志记录器
            exact_set: L1精确去重集合，存储 (url, param, vuln_sub_type) 哈希
            input_point_map: L2输入点映射，存储 (url, param) -> 最严重漏洞
            root_cause_map: L3根因映射，存储根因指纹 -> 关联漏洞列表
            stats: 去重统计信息
        """
        self.logger = Logger()
        self.exact_set: Set[str] = set()
        self.input_point_map: Dict[str, Dict] = {}
        self.root_cause_map: Dict[str, List[Dict]] = {}
        self.stats = {
            'total_input': 0,
            'l1_exact_dedup': 0,
            'l2_input_point_dedup': 0,
            'l3_root_cause_merge': 0,
            'final_output': 0,
        }

    def _normalize_url(self, url: str) -> str:
        """
        标准化URL，去除片段标识符和参数排序差异

        Args:
            url: 原始URL字符串

        Returns:
            标准化后的URL字符串
        """
        try:
            parsed = urlparse(url)
            scheme = parsed.scheme.lower()
            netloc = parsed.netloc.lower()
            path = parsed.path.rstrip('/') or '/'
            params = parse_qs(parsed.query)
            sorted_params = sorted(params.items())
            from urllib.parse import urlencode
            normalized_query = urlencode(sorted_params, doseq=True)
            return urlunparse((scheme, netloc, path, parsed.params, normalized_query, ''))
        except Exception:
            return url

    def _compute_exact_hash(self, vuln: Dict) -> str:
        """
        计算L1精确去重哈希

        基于 URL + 参数名 + 漏洞子类型 生成唯一指纹，
        用于识别完全相同的漏洞报告。

        Args:
            vuln: 漏洞字典，包含 url, parameter, type 等字段

        Returns:
            MD5哈希字符串
        """
        url = self._normalize_url(vuln.get('url', ''))
        param = vuln.get('parameter', '').lower()
        vuln_type = vuln.get('type', '').lower()
        raw = f"{url}|{param}|{vuln_type}"
        return hashlib.md5(raw.encode('utf-8')).hexdigest()

    def _compute_input_point_key(self, vuln: Dict) -> str:
        """
        计算L2输入点去重键

        基于 URL + 参数名 生成输入点标识，
        同一输入点可能被多个检测器报告不同漏洞类型。

        Args:
            vuln: 漏洞字典

        Returns:
            输入点键字符串
        """
        url = self._normalize_url(vuln.get('url', ''))
        param = vuln.get('parameter', '').lower()
        return f"{url}|{param}"

    def _compute_root_cause_key(self, vuln: Dict) -> str:
        """
        计算L3根因关联键

        基于 URL + 参数名 + 请求方法 生成根因标识，
        用于将同一根因触发的多个漏洞聚合在一起。

        Args:
            vuln: 漏洞字典

        Returns:
            根因键字符串
        """
        url = self._normalize_url(vuln.get('url', ''))
        param = vuln.get('parameter', '').lower()
        method = vuln.get('method', 'GET').upper()
        return f"{url}|{param}|{method}"

    def _severity_priority(self, severity: str) -> int:
        """
        获取严重程度优先级数值

        数值越小优先级越高，用于在去重时保留最严重的漏洞。

        Args:
            severity: 严重程度字符串（严重/高危/中危/低危/信息）

        Returns:
            优先级数值，0为最高
        """
        priority_map = {
            '严重': 0,
            '高危': 1,
            '中危': 2,
            '低危': 3,
            '信息': 4,
        }
        return priority_map.get(severity, 5)

    def _merge_vuln_details(self, primary: Dict, secondary: Dict) -> Dict:
        """
        合并两个关联漏洞的详细信息

        将次要漏洞的类型和payload信息追加到主要漏洞中，
        形成更完整的漏洞描述。

        Args:
            primary: 主要漏洞（保留的漏洞）
            secondary: 次要漏洞（被合并的漏洞）

        Returns:
            合并后的漏洞字典
        """
        merged = primary.copy()

        related_types = merged.get('related_types', [])
        if secondary.get('type') and secondary['type'] != primary.get('type'):
            related_types.append(secondary['type'])
        merged['related_types'] = related_types

        related_payloads = merged.get('related_payloads', [])
        if secondary.get('payload') and secondary['payload'] != primary.get('payload'):
            related_payloads.append(secondary['payload'])
        merged['related_payloads'] = related_payloads

        if not merged.get('recommendation') and secondary.get('recommendation'):
            merged['recommendation'] = secondary['recommendation']
        elif merged.get('recommendation') and secondary.get('recommendation'):
            if secondary['recommendation'] not in merged['recommendation']:
                merged['recommendation'] = merged['recommendation'] + '；' + secondary['recommendation']

        return merged

    def deduplicate(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        执行三层去重处理

        处理流程:
        1. L1精确去重: 过滤完全相同的漏洞报告
        2. L2输入点去重: 同一输入点保留最严重的漏洞类型
        3. L3根因合并: 同一根因的多个漏洞聚合为一条

        Args:
            vulnerabilities: 所有检测器产出的原始漏洞列表

        Returns:
            去重后的漏洞列表
        """
        self.stats['total_input'] = len(vulnerabilities)
        self.logger.info(f"去重引擎: 接收 {len(vulnerabilities)} 条漏洞记录")

        # L1: 精确去重
        l1_result = self._l1_exact_dedup(vulnerabilities)
        self.logger.info(
            f"L1精确去重: {len(vulnerabilities)} -> {len(l1_result)} "
            f"(过滤 {self.stats['l1_exact_dedup']} 条重复)"
        )

        # L2: 输入点去重
        l2_result = self._l2_input_point_dedup(l1_result)
        self.logger.info(
            f"L2输入点去重: {len(l1_result)} -> {len(l2_result)} "
            f"(合并 {self.stats['l2_input_point_dedup']} 条同输入点漏洞)"
        )

        # L3: 根因合并
        l3_result = self._l3_root_cause_merge(l2_result)
        self.logger.info(
            f"L3根因合并: {len(l2_result)} -> {len(l3_result)} "
            f"(聚合 {self.stats['l3_root_cause_merge']} 条关联漏洞)"
        )

        self.stats['final_output'] = len(l3_result)
        self.logger.info(
            f"去重完成: {self.stats['total_input']} -> {self.stats['final_output']} "
            f"(总过滤率 {(1 - self.stats['final_output'] / max(self.stats['total_input'], 1)) * 100:.1f}%)"
        )

        return l3_result

    def _l1_exact_dedup(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        L1精确去重

        基于 URL + 参数 + 漏洞子类型 的哈希值进行精确匹配，
        过滤完全相同的漏洞报告（可能来自同一检测器的不同调用轮次）。

        Args:
            vulnerabilities: 原始漏洞列表

        Returns:
            L1去重后的漏洞列表
        """
        result = []
        for vuln in vulnerabilities:
            exact_hash = self._compute_exact_hash(vuln)
            if exact_hash not in self.exact_set:
                self.exact_set.add(exact_hash)
                result.append(vuln)
            else:
                self.stats['l1_exact_dedup'] += 1
        return result

    def _l2_input_point_dedup(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        L2输入点去重

        同一URL的同一参数可能被多个检测器报告不同漏洞类型，
        例如同一参数同时报SQL注入和XSS。
        策略: 保留最严重的漏洞，将其他漏洞类型记录为关联信息。

        Args:
            vulnerabilities: L1去重后的漏洞列表

        Returns:
            L2去重后的漏洞列表
        """
        result = []
        for vuln in vulnerabilities:
            input_key = self._compute_input_point_key(vuln)
            current_priority = self._severity_priority(vuln.get('severity', ''))

            if input_key not in self.input_point_map:
                self.input_point_map[input_key] = vuln
                result.append(vuln)
            else:
                existing_vuln = self.input_point_map[input_key]
                existing_priority = self._severity_priority(existing_vuln.get('severity', ''))

                if current_priority < existing_priority:
                    idx = result.index(existing_vuln)
                    merged = self._merge_vuln_details(vuln, existing_vuln)
                    result[idx] = merged
                    self.input_point_map[input_key] = merged
                else:
                    idx = result.index(existing_vuln)
                    merged = self._merge_vuln_details(existing_vuln, vuln)
                    result[idx] = merged
                    self.input_point_map[input_key] = merged

                self.stats['l2_input_point_dedup'] += 1

        return result

    def _l3_root_cause_merge(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        L3根因合并

        同一根因（同一URL+同一参数+同一请求方法）可能触发多个漏洞，
        例如一个搜索参数同时存在SQL注入、XSS和命令注入。
        策略: 将同一根因的漏洞聚合，主漏洞保留最严重类型，
        关联漏洞信息附加到 related_vulns 字段。

        Args:
            vulnerabilities: L2去重后的漏洞列表

        Returns:
            L3合并后的漏洞列表
        """
        for vuln in vulnerabilities:
            root_key = self._compute_root_cause_key(vuln)
            if root_key not in self.root_cause_map:
                self.root_cause_map[root_key] = [vuln]
            else:
                self.root_cause_map[root_key].append(vuln)
                self.stats['l3_root_cause_merge'] += 1

        result = []
        for root_key, vulns in self.root_cause_map.items():
            if len(vulns) == 1:
                result.append(vulns[0])
                continue

            vulns_sorted = sorted(
                vulns,
                key=lambda v: self._severity_priority(v.get('severity', ''))
            )
            primary = vulns_sorted[0].copy()
            related_vulns = []
            for secondary in vulns_sorted[1:]:
                related_vulns.append({
                    'type': secondary.get('type', ''),
                    'severity': secondary.get('severity', ''),
                    'payload': secondary.get('payload', ''),
                })
                primary = self._merge_vuln_details(primary, secondary)

            primary['related_vulns'] = related_vulns
            primary['root_cause'] = root_key
            result.append(primary)

        return result

    def get_stats(self) -> Dict:
        """
        获取去重统计信息

        Returns:
            包含各层级去重数量的统计字典
        """
        return self.stats.copy()

    def reset(self):
        """
        重置去重引擎状态

        清空所有去重集合和统计信息，用于新一轮扫描。
        """
        self.exact_set.clear()
        self.input_point_map.clear()
        self.root_cause_map.clear()
        self.stats = {
            'total_input': 0,
            'l1_exact_dedup': 0,
            'l2_input_point_dedup': 0,
            'l3_root_cause_merge': 0,
            'final_output': 0,
        }
