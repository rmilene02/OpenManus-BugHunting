"""
OpenManus-BugHunting Fuzzing Module

This module provides comprehensive fuzzing capabilities using Kali Linux tools
and custom fuzzing techniques for input validation testing.
"""

from .web_fuzzer import WebFuzzer
from .parameter_fuzzer import ParameterFuzzer
from .payload_generator import PayloadGenerator

__all__ = [
    'WebFuzzer',
    'ParameterFuzzer',
    'PayloadGenerator'
]