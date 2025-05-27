"""
OpenManus-BugHunting Reporting Module

This module provides comprehensive reporting capabilities for security assessments,
including vulnerability reports, executive summaries, and technical documentation.
"""

from .report_generator import ReportGenerator
from .vulnerability_analyzer import VulnerabilityAnalyzer

__all__ = [
    'ReportGenerator',
    'VulnerabilityAnalyzer'
]