"""OptScale analysis without OptScale services or process-global credentials."""

from .analysis import RULES, analyze
from .aws import scan_aws

__all__ = ["RULES", "analyze", "scan_aws"]
__version__ = "0.1.0"
