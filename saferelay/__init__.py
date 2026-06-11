"""SafeRelay Enterprise CLI — Zero-trust DLP for Linux pipelines."""
from .__main__ import main, __version__
from .client import SafeRelayClient
__all__ = ["main", "__version__", "SafeRelayClient"]
