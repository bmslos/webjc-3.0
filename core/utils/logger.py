#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
日志工具 - 增强版
"""

import os
import sys
import logging
from logging.handlers import RotatingFileHandler
from core.config import LOG_CONFIG


class Logger:
    """日志记录器"""
    
    _instance = None
    _initialized = False
    
    def __new__(cls, verbose: bool = False):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, verbose: bool = False):
        if self._initialized:
            return
        
        self._initialized = True
        self.verbose = verbose
        
        # 创建logger
        self.logger = logging.getLogger('WebScanner-Pro')
        
        # 设置日志级别
        level = logging.DEBUG if verbose else getattr(logging, LOG_CONFIG['level'])
        self.logger.setLevel(level)
        
        # 避免重复添加handler
        if self.logger.handlers:
            return
        
        # 创建格式化器
        formatter = logging.Formatter(
            LOG_CONFIG['format'],
            datefmt=LOG_CONFIG['date_format']
        )
        
        # 控制台handler
        if LOG_CONFIG.get('console_logging', True):
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        # 文件handler
        if LOG_CONFIG.get('file_logging', True):
            log_file = LOG_CONFIG.get('log_file', 'scanner.log')
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                os.makedirs(log_dir, exist_ok=True)
            
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=LOG_CONFIG.get('max_bytes', 10 * 1024 * 1024),
                backupCount=LOG_CONFIG.get('backup_count', 3),
                encoding='utf-8'
            )
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def debug(self, message: str):
        """记录DEBUG级别日志"""
        self.logger.debug(message)
    
    def info(self, message: str):
        """记录INFO级别日志"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """记录WARNING级别日志"""
        self.logger.warning(message)
    
    def error(self, message: str):
        """记录ERROR级别日志"""
        self.logger.error(message)
    
    def critical(self, message: str):
        """记录CRITICAL级别日志"""
        self.logger.critical(message)
