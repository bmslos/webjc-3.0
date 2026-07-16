# 示例插件: XXE(XML External Entity)检测器
#
# 这是一个薄封装示例——实际检测逻辑由内置检测器
# core.detectors.xxe.XXEDetector 提供，插件直接复用以避免代码重复。
#
# 如果需要自定义检测逻辑，可以参考 core/detectors/base.py 中的
# BaseDetector 基类，继承后实现 scan() 方法即可。

from core.detectors.xxe import XXEDetector

__all__ = ['XXEDetector']
