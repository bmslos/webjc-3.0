# -*- coding: utf-8 -*-
"""Logger 单例单元测试"""

import logging
import pytest
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
