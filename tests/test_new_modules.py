#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
新增模块单元测试 - 验证去重引擎、验证引擎、任务管理器和AI分析器
"""

import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))


def test_dedup_engine():
    """测试全局交叉去重引擎"""
    from core.dedup_engine import DedupEngine

    engine = DedupEngine()

    vulns = [
        {'url': 'http://example.com/page?id=1', 'parameter': 'id',
         'type': 'SQL注入(错误回显)', 'severity': '高危', 'payload': "' OR 1=1"},
        {'url': 'http://example.com/page?id=1', 'parameter': 'id',
         'type': 'SQL注入(错误回显)', 'severity': '高危', 'payload': "' OR 1=1"},
        {'url': 'http://example.com/page?id=1', 'parameter': 'id',
         'type': 'XSS(反射型)', 'severity': '高危', 'payload': '<script>'},
        {'url': 'http://example.com/page?id=1', 'parameter': 'id',
         'type': '命令注入', 'severity': '高危', 'payload': '; id'},
        {'url': 'http://example.com/page?name=test', 'parameter': 'name',
         'type': 'XSS(反射型)', 'severity': '高危', 'payload': '<script>'},
    ]

    result = engine.deduplicate(vulns)
    stats = engine.get_stats()

    assert stats['total_input'] == 5, f"输入数量错误: {stats['total_input']}"
    assert stats['l1_exact_dedup'] == 1, f"L1去重数量错误: {stats['l1_exact_dedup']}"
    assert stats['final_output'] < 5, f"输出数量应小于输入: {stats['final_output']}"

    print(f"[PASS] 去重引擎: {stats['total_input']} -> {stats['final_output']} 条")
    for v in result:
        related = v.get('related_types', [])
        print(f"       {v['type']} | param={v['parameter']} | related={related}")


def test_parameter_context():
    """测试参数上下文推断"""
    from core.verification import ParameterContext

    assert ParameterContext.infer_type('user_id') == ParameterContext.PARAM_TYPE_NUMERIC
    assert ParameterContext.infer_type('file_path') == ParameterContext.PARAM_TYPE_FILEPATH
    assert ParameterContext.infer_type('callback_url') == ParameterContext.PARAM_TYPE_URL
    assert ParameterContext.infer_type('email') == ParameterContext.PARAM_TYPE_EMAIL
    assert ParameterContext.infer_type('cmd') == ParameterContext.PARAM_TYPE_COMMAND
    assert ParameterContext.infer_type('unknown_xyz') == ParameterContext.PARAM_TYPE_UNKNOWN

    form_ctx = {'type': 'number'}
    assert ParameterContext.infer_type('data', form_context=form_ctx) == ParameterContext.PARAM_TYPE_NUMERIC

    print("[PASS] 参数上下文推断: 所有类型推断正确")


def test_task_manager():
    """测试任务管理器"""
    test_db = 'data/test_scan_tasks.db'
    if os.path.exists(test_db):
        os.remove(test_db)

    from core.task_manager import TaskManager

    tm = TaskManager(db_path=test_db)

    task_id = tm.create_task('http://example.com', priority=3)
    assert task_id.startswith('task_'), f"任务ID格式错误: {task_id}"

    task = tm.get_task(task_id)
    assert task is not None, "任务不应为None"
    assert task['target_url'] == 'http://example.com'
    assert task['status'] == 'pending'

    tm.update_task_status(task_id, 'running', progress=0.5)
    task = tm.get_task(task_id)
    assert task['status'] == 'running'
    assert task['progress'] == 0.5

    batch_ids = tm.create_batch_tasks([
        'http://site1.com',
        'http://site2.com',
        'invalid-url',
    ])
    assert len(batch_ids) == 2, f"批量创建数量错误: {len(batch_ids)}"

    stats = tm.get_statistics()
    assert stats['tasks'].get('pending', 0) + stats['tasks'].get('running', 0) == 3, f"统计错误: {stats}"

    pending = tm.get_pending_tasks()
    assert len(pending) >= 2

    tm.delete_task(task_id)

    if os.path.exists(test_db):
        os.remove(test_db)

    print("[PASS] 任务管理器: 创建/更新/批量/统计/删除全部正确")


def test_ai_analyzer_rule_based():
    """测试AI分析器规则引擎降级模式"""
    from core.ai_analyzer import AIAnalyzer

    analyzer = AIAnalyzer(config={'api_key': ''})
    assert not analyzer.enabled, "无API Key时不应启用LLM"

    vulns = [
        {'type': 'XSS(反射型)', 'severity': '高危', 'url': 'http://example.com',
         'parameter': 'id', 'method': 'GET', 'payload': '<script>',
         'confidence': 0.5, 'param_context': {'type': 'numeric'}},
        {'type': 'SQL注入', 'severity': '高危', 'url': 'http://example.com',
         'parameter': 'email', 'method': 'GET', 'payload': "' OR 1=1",
         'confidence': 0.5, 'param_context': {'type': 'email'}},
        {'type': 'SQL注入', 'severity': '高危', 'url': 'http://example.com',
         'parameter': 'query', 'method': 'GET', 'payload': "' OR 1=1",
         'confidence': 0.5, 'param_context': {'type': 'string'}},
    ]

    filtered = analyzer.filter_false_positives(vulns)

    rejected = sum(
        1 for v in filtered
        if v.get('verification_status') == 'rejected_by_rule'
    )
    assert rejected >= 1, f"规则引擎应至少过滤1条误报: {rejected}"

    print(f"[PASS] AI分析器规则降级: 过滤 {rejected} 条误报")

    payloads = analyzer.generate_smart_payloads(
        'http://example.com', 'id', '1', 'numeric', 'sqli'
    )
    assert len(payloads) > 0, "规则payload生成不应为空"
    print(f"[PASS] 智能payload生成(规则): 生成 {len(payloads)} 个payload")


def test_scanner_integration():
    """测试扫描引擎集成（仅验证初始化）"""
    from core.scanner import EnhancedWebScanner

    scanner = EnhancedWebScanner(
        target='http://example.com',
        enable_dedup=True,
        enable_verification=False,
        enable_ai=False,
    )

    assert scanner.dedup_engine is not None, "去重引擎应已初始化"
    assert scanner.verification_engine is None, "验证引擎不应初始化"
    assert scanner.ai_analyzer is None, "AI分析器不应初始化"
    assert scanner.enable_dedup is True
    assert scanner.enable_verification is False
    assert scanner.enable_ai is False

    scanner2 = EnhancedWebScanner(
        target='http://example.com',
        enable_dedup=False,
        enable_verification=False,
        enable_ai=False,
    )
    assert scanner2.dedup_engine is None, "禁用时去重引擎不应初始化"

    print("[PASS] 扫描引擎集成: 初始化参数正确")


if __name__ == '__main__':
    print("=" * 60)
    print("新增模块单元测试")
    print("=" * 60)

    test_dedup_engine()
    test_parameter_context()
    test_task_manager()
    test_ai_analyzer_rule_based()
    test_scanner_integration()

    print()
    print("=" * 60)
    print("所有测试通过!")
    print("=" * 60)
