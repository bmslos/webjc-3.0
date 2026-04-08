#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
插件管理器 - 支持动态加载和卸载检测器插件
"""

import os
import sys
import importlib
import importlib.util
from typing import Dict, List, Any, Optional, Type
from core.config import PLUGIN_CONFIG
from core.utils.logger import Logger


class PluginManager:
    """插件管理器"""
    
    def __init__(self, plugin_dir: Optional[str] = None):
        """
        初始化插件管理器
        
        Args:
            plugin_dir: 插件目录路径
        """
        self.plugin_dir = plugin_dir or PLUGIN_CONFIG.get('plugin_dir', 'plugins')
        self.logger = Logger()
        self.plugins: Dict[str, Any] = {}
        self.plugin_instances: Dict[str, Any] = {}
    
    def discover_plugins(self) -> List[str]:
        """
        自动发现插件目录中的所有插件
        
        Returns:
            插件名称列表
        """
        plugin_names = []
        
        if not os.path.exists(self.plugin_dir):
            self.logger.warning(f"插件目录不存在: {self.plugin_dir}")
            return plugin_names
        
        # 扫描插件目录
        for item in os.listdir(self.plugin_dir):
            item_path = os.path.join(self.plugin_dir, item)
            
            # 检查是否为Python文件
            if item.endswith('.py') and not item.startswith('_'):
                plugin_name = item[:-3]  # 移除.py后缀
                plugin_names.append(plugin_name)
            
            # 检查是否为Python包
            elif os.path.isdir(item_path) and os.path.exists(os.path.join(item_path, '__init__.py')):
                plugin_names.append(item)
        
        self.logger.info(f"发现 {len(plugin_names)} 个插件")
        return plugin_names
    
    def load_plugin(self, plugin_name: str) -> Optional[Type]:
        """
        加载单个插件
        
        Args:
            plugin_name: 插件名称
            
        Returns:
            插件类
        """
        if plugin_name in self.plugins:
            self.logger.debug(f"插件已加载: {plugin_name}")
            return self.plugins[plugin_name]
        
        # 尝试从插件目录加载
        plugin_path = os.path.join(self.plugin_dir, f"{plugin_name}.py")
        package_path = os.path.join(self.plugin_dir, plugin_name)
        
        try:
            if os.path.exists(plugin_path):
                # 加载单个Python文件
                spec = importlib.util.spec_from_file_location(
                    f"plugins.{plugin_name}",
                    plugin_path
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[f"plugins.{plugin_name}"] = module
                    spec.loader.exec_module(module)
                    
                    # 查找插件类
                    plugin_class = self._find_plugin_class(module, plugin_name)
                    if plugin_class:
                        self.plugins[plugin_name] = plugin_class
                        self.logger.info(f"成功加载插件: {plugin_name}")
                        return plugin_class
            
            elif os.path.exists(package_path) and os.path.exists(os.path.join(package_path, '__init__.py')):
                # 加载Python包
                module = importlib.import_module(f"plugins.{plugin_name}")
                plugin_class = self._find_plugin_class(module, plugin_name)
                if plugin_class:
                    self.plugins[plugin_name] = plugin_class
                    self.logger.info(f"成功加载插件包: {plugin_name}")
                    return plugin_class
            
            self.logger.error(f"无法加载插件: {plugin_name}")
            return None
            
        except Exception as e:
            self.logger.error(f"加载插件失败 {plugin_name}: {str(e)}")
            return None
    
    def load_all_plugins(self) -> Dict[str, Type]:
        """
        加载所有可用的插件
        
        Returns:
            插件名称到插件类的映射
        """
        plugin_names = self.discover_plugins()
        
        enabled_plugins = PLUGIN_CONFIG.get('enabled_plugins', [])
        disabled_plugins = PLUGIN_CONFIG.get('disabled_plugins', [])
        
        for plugin_name in plugin_names:
            # 检查是否被禁用
            if disabled_plugins and plugin_name in disabled_plugins:
                self.logger.info(f"插件已禁用,跳过: {plugin_name}")
                continue
            
            # 检查是否在启用列表中(如果指定了)
            if enabled_plugins and plugin_name not in enabled_plugins:
                self.logger.debug(f"插件未在启用列表中,跳过: {plugin_name}")
                continue
            
            self.load_plugin(plugin_name)
        
        self.logger.info(f"已加载 {len(self.plugins)} 个插件")
        return self.plugins
    
    def instantiate_plugin(self, plugin_name: str, **kwargs) -> Optional[Any]:
        """
        实例化插件
        
        Args:
            plugin_name: 插件名称
            **kwargs: 插件初始化参数
            
        Returns:
            插件实例
        """
        if plugin_name not in self.plugins:
            plugin_class = self.load_plugin(plugin_name)
            if not plugin_class:
                return None
        
        plugin_class = self.plugins[plugin_name]
        
        try:
            instance = plugin_class(**kwargs)
            self.plugin_instances[plugin_name] = instance
            self.logger.debug(f"成功实例化插件: {plugin_name}")
            return instance
        except Exception as e:
            self.logger.error(f"实例化插件失败 {plugin_name}: {str(e)}")
            return None
    
    def get_plugin(self, plugin_name: str) -> Optional[Any]:
        """获取已实例化的插件"""
        return self.plugin_instances.get(plugin_name)
    
    def get_all_plugins(self) -> Dict[str, Type]:
        """获取所有已加载的插件"""
        return self.plugins.copy()
    
    def get_all_instances(self) -> Dict[str, Any]:
        """获取所有已实例化的插件"""
        return self.plugin_instances.copy()
    
    def unload_plugin(self, plugin_name: str):
        """卸载插件"""
        self.plugins.pop(plugin_name, None)
        self.plugin_instances.pop(plugin_name, None)
        self.logger.info(f"已卸载插件: {plugin_name}")
    
    def _find_plugin_class(self, module, plugin_name: str) -> Optional[Type]:
        """
        在模块中查找插件类
        
        Args:
            module: Python模块
            plugin_name: 插件名称
            
        Returns:
            插件类
        """
        # 优先查找以Detector/Scanner/Plugin结尾的类
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type):
                # 检查类名是否匹配插件名称
                if (attr_name.lower().endswith(('detector', 'scanner', 'plugin')) and
                    plugin_name.lower() in attr_name.lower()):
                    return attr
        
        # 如果没找到,返回第一个公开的类
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and not attr_name.startswith('_'):
                return attr
        
        return None
