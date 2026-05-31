import pytest
from unittest.mock import patch, MagicMock
from cyberai.agents.recon.nmap_tool import _parse_ports
from cyberai.agents.recon.dns_tool import run_dns


def test_parse_ports_empty():
    """Should return empty list for empty nmap output"""
    result = _parse_ports("")
    assert result == []


def test_parse_ports_open():
    """Should parse open ports from nmap XML"""
    xml = """
    <port protocol="tcp" portid="80">
    <state state="open" reason="syn-ack"/>
    <service name="http" product="nginx"/>
    </port>
    """
    ports = _parse_ports(xml)
    assert len(ports) == 1
    assert ports[0]["port"] == 80
    assert ports[0]["service"] == "http"


def test_parse_ports_filters_closed():
    """Should not include closed ports"""
    xml = """
    <port protocol="tcp" portid="22">
    <state state="closed" reason="reset"/>
    <service name="ssh"/>
    </port>
    """
    ports = _parse_ports(xml)
    assert ports == []
