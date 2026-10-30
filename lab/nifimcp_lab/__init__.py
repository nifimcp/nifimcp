"""Disposable NiFi lab tooling for NiFiMCP.

This package is deliberately OUTSIDE the ``nifimcp`` runtime package. It holds
the only code in the repository that changes a NiFi instance, and it may only
target a lab that it created and recorded in a lab ownership manifest.

The MCP runtime never imports this package (enforced by
tests/security/test_lab_boundary.py).
"""

LAB_VERSION = "0.1.0"
