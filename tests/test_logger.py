# -*- coding: utf-8 -*-
"""Logger 单例单元测试"""

import logging
from core.utils.logger import Logger


class TestLogger:
    """Logger 单例测试"""

    def test_singleton_returns_same_instance(self):
        """测试单例返回同一实例"""
        logger1 = Logger()
        logger2 = Logger()
        assert logger1 is logger2

    def test_accepts_arbitrary_kwargs(self):
        """测试接受任意关键字参数不崩溃（H4修复）"""
        # 之前 Logger(target=...) 会崩溃，现在应正常
        logger = Logger(target='test', foo='bar', verbose=True)
        assert logger is not None

    def test_accepts_arbitrary_positional_args(self):
        """测试接受任意位置参数不崩溃"""
        logger = Logger('some_arg', 'another_arg')
        assert logger is not None

    def test_set_verbose_changes_level(self):
        """测试 set_verbose 切换日志级别"""
        logger = Logger()
        logger.set_verbose(True)
        assert logger.verbose is True
        assert logger.logger.level == logging.DEBUG

        logger.set_verbose(False)
        assert logger.verbose is False

    def test_log_methods_exist(self):
        """测试所有日志方法存在"""
        logger = Logger()
        assert hasattr(logger, 'debug')
        assert hasattr(logger, 'info')
        assert hasattr(logger, 'warning')
        assert hasattr(logger, 'error')
        assert hasattr(logger, 'critical')

    def test_log_methods_callable(self):
        """测试日志方法可调用（不抛异常）"""
        logger = Logger()
        logger.debug("test debug message")
        logger.info("test info message")
        logger.warning("test warning message")
        logger.error("test error message")
        logger.critical("test critical message")

    def test_quiet_mode_wins_over_later_calls(self):
        """测试quiet模式：后续无quiet参数的Logger()调用不重置WARNING级别"""
        # 重置单例以模拟首次以quiet初始化
        Logger._instance = None
        Logger._initialized = False
        try:
            log1 = Logger(verbose=False, quiet=True)
            assert log1.logger.level == logging.WARNING

            # 模拟其他模块后续调用 Logger()：不应把级别重置回INFO
            log2 = Logger(verbose=False)
            assert log2 is log1
            assert log2.logger.level == logging.WARNING
        finally:
            # 恢复默认单例状态，避免影响其他测试
            Logger._instance = None
            Logger._initialized = False
            Logger()
