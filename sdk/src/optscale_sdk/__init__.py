"""OptScale analysis without OptScale services or process-global credentials."""

from .analysis import RULES, analyze
from .anomalies import detect_anomalies
from .aws import collect_resources_aws, scan_anomalies_aws, scan_aws
from .resources import inventory
from .expenses import collect_expenses_aws, expenses_report

__all__ = ["RULES", "analyze", "scan_aws", "inventory", "collect_resources_aws",
           "detect_anomalies", "scan_anomalies_aws", "collect_expenses_aws", "expenses_report"]
__version__ = "0.2.0"
