"""Bounded adapters for external hunt and model systems.

The integrations package intentionally contains transport and normalization
code only.  Workflow and policy decisions belong to the application layers.
"""

from .errors import AdapterError, AdapterFailure
from .splunk import (
    CancellationToken,
    SplunkConnectionConfig,
    SplunkConnector,
    SplunkDiscovery,
    SplunkDiscoveryItem,
)

__all__ = [
    "AdapterError",
    "AdapterFailure",
    "CancellationToken",
    "SplunkConnectionConfig",
    "SplunkConnector",
    "SplunkDiscovery",
    "SplunkDiscoveryItem",
]
