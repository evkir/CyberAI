"""The single place the package version is written.

Four gates read __version__ from here and compare it to what the README badge,
the changelog heading, the CLI and the MCP server each claim. A version
assigned in any of those places instead would agree with itself and with
nothing else.
"""

__version__ = "1.7.0"
__author__ = "evkir"
__description__ = "CyberAI — AI-native multi-agent pentest platform"
