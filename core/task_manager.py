#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
多目标扫描任务管理器

核心功能:
1. 多目标批量扫描 - 支持从文件或列表加载多个扫描目标
2. 任务持久化 - 基于SQLite存储扫描任务和漏洞数据
3. 任务状态管理 - 跟踪任务进度（排队/运行中/完成/失败/取消）
4. 断点续传 - 支持从中断位置恢复扫描
5. 任务优先级 - 支持任务优先级排序
6. 历史查询 - 查询历史扫描记录和漏洞数据
"""

import os
import json
import time
import sqlite3
import threading
from typing import Dict, List, Optional, Any
from datetime import datetime
from core.utils.logger import Logger


class TaskManager:
    """
    多目标扫描任务管理器

    使用SQLite数据库持久化存储扫描任务和漏洞结果，
    支持多目标批量扫描、任务状态跟踪和断点续传。

    数据库表结构:
    - scan_tasks: 扫描任务表，存储任务信息和状态
    - vulnerabilities: 漏洞表，存储每个任务发现的漏洞详情
    """

    TASK_STATUS_PENDING = 'pending'
    TASK_STATUS_RUNNING = 'running'
    TASK_STATUS_COMPLETED = 'completed'
    TASK_STATUS_FAILED = 'failed'
    TASK_STATUS_CANCELLED = 'cancelled'

    def __init__(self, db_path: str = 'data/scan_tasks.db'):
        """
        初始化任务管理器

        Args:
            db_path: SQLite数据库文件路径，默认存储在 data/scan_tasks.db
        """
        self.db_path = db_path
        self.logger = Logger()
        self._lock = threading.Lock()

        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        self._init_database()

    def __enter__(self):
        """上下文管理器入口，支持 with TaskManager() as tm 用法"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器退出（每次方法调用创建新连接，无需在此关闭）"""
        pass

    def _init_database(self):
        """
        初始化数据库表结构

        创建 scan_tasks 和 vulnerabilities 两张表，
        如果表已存在则跳过创建。
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_tasks (
                    task_id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',
                    priority INTEGER DEFAULT 5,
                    progress REAL DEFAULT 0.0,
                    config_json TEXT,
                    result_json TEXT,
                    vuln_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    info_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    error_message TEXT,
                    report_path TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    vuln_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    url TEXT NOT NULL,
                    parameter TEXT,
                    method TEXT,
                    payload TEXT,
                    description TEXT,
                    recommendation TEXT,
                    verification_status TEXT,
                    confidence REAL,
                    param_context_json TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (task_id) REFERENCES scan_tasks(task_id)
                )
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_vulns_task_id
                ON vulnerabilities(task_id)
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_vulns_severity
                ON vulnerabilities(severity)
            ''')

            cursor.execute('''
                CREATE INDEX IF NOT EXISTS idx_tasks_status
                ON scan_tasks(status)
            ''')

            conn.commit()
            conn.close()
            self.logger.info(f"任务数据库已初始化: {self.db_path}")

    def create_task(self, target_url: str, priority: int = 5,
                    config: Optional[Dict] = None) -> str:
        """
        创建扫描任务

        Args:
            target_url: 扫描目标URL
            priority: 任务优先级（1-10，1最高）
            config: 扫描配置字典（可选）

        Returns:
            任务ID字符串
        """
        task_id = f"task_{int(time.time() * 1000)}_{hash(target_url) % 10000:04d}"
        config_json = json.dumps(config or {}, ensure_ascii=False)
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scan_tasks
                (task_id, target_url, status, priority, config_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (task_id, target_url, self.TASK_STATUS_PENDING,
                  priority, config_json, created_at))
            conn.commit()
            conn.close()

        self.logger.info(f"创建扫描任务: {task_id} -> {target_url}")
        return task_id

    def create_batch_tasks(self, target_urls: List[str],
                           priority: int = 5,
                           config: Optional[Dict] = None) -> List[str]:
        """
        批量创建扫描任务

        Args:
            target_urls: 扫描目标URL列表
            priority: 任务优先级
            config: 扫描配置字典

        Returns:
            任务ID列表
        """
        task_ids = []
        for url in target_urls:
            url = url.strip()
            if url and url.startswith(('http://', 'https://')):
                task_id = self.create_task(url, priority, config)
                task_ids.append(task_id)
            else:
                self.logger.warning(f"跳过无效URL: {url}")

        self.logger.info(f"批量创建 {len(task_ids)} 个扫描任务")
        return task_ids

    def load_targets_from_file(self, file_path: str,
                               priority: int = 5,
                               config: Optional[Dict] = None) -> List[str]:
        """
        从文件加载扫描目标并创建任务

        文件格式: 每行一个URL，支持 # 开头的注释行和空行。

        Args:
            file_path: 目标URL文件路径
            priority: 任务优先级
            config: 扫描配置字典

        Returns:
            任务ID列表
        """
        if not os.path.exists(file_path):
            self.logger.error(f"目标文件不存在: {file_path}")
            return []

        urls = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls.append(line)

        self.logger.info(f"从文件加载 {len(urls)} 个目标: {file_path}")
        return self.create_batch_tasks(urls, priority, config)

    def update_task_status(self, task_id: str, status: str,
                           progress: float = 0.0,
                           error_message: str = ''):
        """
        更新任务状态

        Args:
            task_id: 任务ID
            status: 新状态（pending/running/completed/failed/cancelled）
            progress: 任务进度（0.0-1.0）
            error_message: 错误信息（失败时填写）
        """
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            if status == self.TASK_STATUS_RUNNING:
                cursor.execute('''
                    UPDATE scan_tasks
                    SET status = ?, progress = ?, started_at = ?
                    WHERE task_id = ?
                ''', (status, progress, now, task_id))
            elif status in (self.TASK_STATUS_COMPLETED, self.TASK_STATUS_FAILED,
                            self.TASK_STATUS_CANCELLED):
                cursor.execute('''
                    UPDATE scan_tasks
                    SET status = ?, progress = ?, completed_at = ?,
                        error_message = ?
                    WHERE task_id = ?
                ''', (status, progress, now, error_message, task_id))
            else:
                cursor.execute('''
                    UPDATE scan_tasks SET status = ?, progress = ?
                    WHERE task_id = ?
                ''', (status, progress, task_id))

            conn.commit()
            conn.close()

    def save_task_result(self, task_id: str, result: Dict):
        """
        保存任务扫描结果

        将扫描结果摘要更新到任务表，并将漏洞详情写入漏洞表。

        Args:
            task_id: 任务ID
            result: 扫描结果字典，包含 vulnerabilities 等字段
        """
        vulnerabilities = result.get('vulnerabilities', [])
        severity_count = {'严重': 0, '高危': 0, '中危': 0, '低危': 0, '信息': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', '信息')
            severity_count[severity] = severity_count.get(severity, 0) + 1

        result_summary = {
            'target': result.get('target', ''),
            'scan_time': result.get('scan_time', ''),
            'scan_stats': result.get('scan_stats', {}),
        }
        result_json = json.dumps(result_summary, ensure_ascii=False)

        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                UPDATE scan_tasks
                SET result_json = ?, vuln_count = ?,
                    high_count = ?, medium_count = ?,
                    low_count = ?, info_count = ?,
                    progress = 1.0, status = ?,
                    completed_at = ?
                WHERE task_id = ?
            ''', (
                result_json,
                len(vulnerabilities),
                severity_count.get('严重', 0) + severity_count.get('高危', 0),
                severity_count.get('中危', 0),
                severity_count.get('低危', 0),
                severity_count.get('信息', 0),
                self.TASK_STATUS_COMPLETED,
                datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                task_id,
            ))

            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            vuln_rows = [
                (
                    task_id,
                    vuln.get('type', ''),
                    vuln.get('severity', ''),
                    vuln.get('url', ''),
                    vuln.get('parameter', ''),
                    vuln.get('method', ''),
                    vuln.get('payload', ''),
                    vuln.get('description', ''),
                    vuln.get('recommendation', ''),
                    vuln.get('verification_status', ''),
                    vuln.get('confidence', 0.0),
                    json.dumps(vuln.get('param_context', {}), ensure_ascii=False),
                    now,
                )
                for vuln in vulnerabilities
            ]
            cursor.executemany('''
                INSERT INTO vulnerabilities
                (task_id, vuln_type, severity, url, parameter, method,
                 payload, description, recommendation,
                 verification_status, confidence, param_context_json,
                 created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', vuln_rows)

            conn.commit()
            conn.close()

        self.logger.info(
            f"保存任务结果: {task_id}, "
            f"漏洞数: {len(vulnerabilities)}"
        )

    def get_pending_tasks(self, limit: int = 10) -> List[Dict]:
        """
        获取待执行的扫描任务

        按优先级排序返回状态为 pending 的任务列表。

        Args:
            limit: 最大返回数量

        Returns:
            待执行任务字典列表
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM scan_tasks
                WHERE status = ?
                ORDER BY priority ASC, created_at ASC
                LIMIT ?
            ''', (self.TASK_STATUS_PENDING, limit))
            rows = cursor.fetchall()
            conn.close()

        return [dict(row) for row in rows]

    def get_task(self, task_id: str) -> Optional[Dict]:
        """
        获取单个任务详情

        Args:
            task_id: 任务ID

        Returns:
            任务详情字典，不存在返回None
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM scan_tasks WHERE task_id = ?', (task_id,)
            )
            row = cursor.fetchone()
            conn.close()

        return dict(row) if row else None

    def get_task_vulnerabilities(self, task_id: str) -> List[Dict]:
        """
        获取指定任务的漏洞列表

        Args:
            task_id: 任务ID

        Returns:
            漏洞字典列表
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM vulnerabilities WHERE task_id = ?', (task_id,)
            )
            rows = cursor.fetchall()
            conn.close()

        return [dict(row) for row in rows]

    def list_tasks(self, status: Optional[str] = None,
                   limit: int = 50) -> List[Dict]:
        """
        列出扫描任务

        Args:
            status: 按状态过滤（可选）
            limit: 最大返回数量

        Returns:
            任务字典列表
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            if status:
                cursor.execute('''
                    SELECT * FROM scan_tasks
                    WHERE status = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                ''', (status, limit))
            else:
                cursor.execute('''
                    SELECT * FROM scan_tasks
                    ORDER BY created_at DESC
                    LIMIT ?
                ''', (limit,))

            rows = cursor.fetchall()
            conn.close()

        return [dict(row) for row in rows]

    def get_interrupted_tasks(self) -> List[Dict]:
        """
        获取可恢复的中断任务

        返回状态为 running 或 pending 但已超时的任务，
        用于断点续传。

        Returns:
            可恢复任务列表
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM scan_tasks
                WHERE status IN (?, ?)
                ORDER BY priority ASC, created_at ASC
            ''', (self.TASK_STATUS_RUNNING, self.TASK_STATUS_PENDING))
            rows = cursor.fetchall()
            conn.close()

        return [dict(row) for row in rows]

    def delete_task(self, task_id: str) -> bool:
        """
        删除任务及其关联的漏洞数据

        Args:
            task_id: 任务ID

        Returns:
            是否删除成功
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute(
                'DELETE FROM vulnerabilities WHERE task_id = ?', (task_id,)
            )
            cursor.execute(
                'DELETE FROM scan_tasks WHERE task_id = ?', (task_id,)
            )
            deleted = cursor.rowcount > 0
            conn.commit()
            conn.close()

        if deleted:
            self.logger.info(f"已删除任务: {task_id}")
        return deleted

    def get_statistics(self) -> Dict:
        """
        获取任务统计信息

        Returns:
            包含各状态任务计数和漏洞总计的统计字典
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT status, COUNT(*) as count
                FROM scan_tasks GROUP BY status
            ''')
            status_counts = dict(cursor.fetchall())

            cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
            total_vulns = cursor.fetchone()[0]

            cursor.execute('''
                SELECT severity, COUNT(*) as count
                FROM vulnerabilities GROUP BY severity
            ''')
            severity_counts = dict(cursor.fetchall())

            conn.close()

        return {
            'tasks': status_counts,
            'total_vulnerabilities': total_vulns,
            'vulnerabilities_by_severity': severity_counts,
        }

    def update_task_report_path(self, task_id: str, report_path: str):
        """
        更新任务的报告文件路径

        Args:
            task_id: 任务ID
            report_path: 报告文件路径
        """
        with self._lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE scan_tasks SET report_path = ? WHERE task_id = ?
            ''', (report_path, task_id))
            conn.commit()
            conn.close()
