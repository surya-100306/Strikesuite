"""
StrikeSuite Core Modules
Advanced Cybersecurity Testing Framework
"""

__version__ = "1.0.0"
__author__ = "StrikeSuite Development Team"

# Import modules with error handling to avoid import failures
try:
    from .scanner import NetworkScanner
except ImportError:
    NetworkScanner = None

try:
    from .api_tester import APITester
except ImportError:
    APITester = None

try:
    from .vulnerability_scanner import VulnerabilityScanner
except ImportError:
    VulnerabilityScanner = None

try:
    from .exploit_module import ExploitModule
except ImportError:
    ExploitModule = None

try:
    from .brute_forcer import BruteForcer
except ImportError:
    BruteForcer = None

try:
    from .post_exploitation import PostExploitation
except ImportError:
    PostExploitation = None

try:
    from .reporter import ReportGenerator
except ImportError:
    ReportGenerator = None

try:
    from .plugin_manager import PluginManager
except ImportError:
    PluginManager = None

try:
    from .assessment_results import AssessmentResultsManager, results_manager
except ImportError:
    AssessmentResultsManager = None
    results_manager = None

try:
    from .report_aggregator import ReportDataAggregator, report_aggregator
except ImportError:
    ReportDataAggregator = None
    report_aggregator = None

__all__ = [
    'NetworkScanner',
    'APITester', 
    'VulnerabilityScanner',
    'ExploitModule',
    'BruteForcer',
    'PostExploitation',
    'ReportGenerator',
    'PluginManager',
    'AssessmentResultsManager',
    'results_manager',
    'ReportDataAggregator',
    'report_aggregator'
]
