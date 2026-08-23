"""
Predefined Scan Profiles Registry
==================================
Centralized repository of safe, server-enforced Nmap scan profiles.
Users select by profile identifier only. Custom flags or raw NSE script inputs
are strictly prohibited.
"""

from typing import Dict, Any, Optional

SCAN_PROFILES: Dict[str, Dict[str, Any]] = {
    "host_discovery": {
        "id": "host_discovery",
        "name": "Host Discovery",
        "command_summary": "nmap -sn",
        "description": "Determine whether the target host is reachable on the local network without performing port scans.",
        "scan_type": "ICMP & ARP Ping Sweep",
        "estimated_duration": "~5-15s",
        "arguments": ["-sn"]
    },
    "basic_port_scan": {
        "id": "basic_port_scan",
        "name": "Basic Port Scan",
        "command_summary": "nmap -F",
        "description": "Rapidly scan the top 100 most common TCP ports for open listening services.",
        "scan_type": "Fast TCP Port Scan",
        "estimated_duration": "~10-30s",
        "arguments": ["-F", "-T4"]
    },
    "service_enumeration": {
        "id": "service_enumeration",
        "name": "Service Enumeration",
        "command_summary": "nmap -sV",
        "description": "Probe open TCP ports to determine service names and software version details.",
        "scan_type": "TCP Service & Version Probe",
        "estimated_duration": "~30-60s",
        "arguments": ["-sV", "--version-intensity", "5", "-T4"]
    },
    "service_default_nse": {
        "id": "service_default_nse",
        "name": "Service + Default NSE",
        "command_summary": "nmap -sV -sC",
        "description": "Perform service version detection combined with Nmap's default safe script suite.",
        "scan_type": "Service + Safe NSE Analysis",
        "estimated_duration": "~45-90s",
        "arguments": ["-sV", "-sC", "-T4"]
    },
    "http_enumeration": {
        "id": "http_enumeration",
        "name": "HTTP Enumeration",
        "command_summary": "nmap -p 80,443 --script http-*",
        "description": "Targeted inspection of web servers on ports 80 and 443 (title grab, headers, and methods).",
        "scan_type": "Targeted Web Service Inspection",
        "estimated_duration": "~20-45s",
        "arguments": ["-p", "80,443", "--script", "http-title,http-headers,http-methods", "-sV", "-T4"]
    },
    "ssh_enumeration": {
        "id": "ssh_enumeration",
        "name": "SSH Enumeration",
        "command_summary": "nmap -p 22 --script ssh2-*",
        "description": "Targeted inspection of SSH servers on port 22 (supported ciphers, key exchange algorithms, and host keys).",
        "scan_type": "Targeted SSH Protocol Inspection",
        "estimated_duration": "~15-30s",
        "arguments": ["-p", "22", "--script", "ssh2-enum-algos,ssh-hostkey", "-sV", "-T4"]
    },
    "comprehensive_lab_scan": {
        "id": "comprehensive_lab_scan",
        "name": "Comprehensive Lab Scan",
        "command_summary": "nmap -sV -p- -T4",
        "description": "Full TCP assessment across all 65,535 ports with service version detection in an isolated lab.",
        "scan_type": "Full TCP Port & Service Assessment",
        "estimated_duration": "~60-180s",
        "arguments": ["-sV", "-p-", "-T4"]
    }
}

DEFAULT_PROFILE = "service_default_nse"

def get_scan_profiles() -> Dict[str, Dict[str, Any]]:
    """Returns the complete immutable registry of predefined scan profiles."""
    return SCAN_PROFILES

def get_profile_by_id(profile_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Returns the profile dictionary for a given profile ID or None if not recognized."""
    if not profile_id or not isinstance(profile_id, str):
        return None
    return SCAN_PROFILES.get(profile_id.strip().lower())

def is_valid_profile(profile_id: Optional[str]) -> bool:
    """Checks whether the supplied profile ID is in the predefined registry."""
    return get_profile_by_id(profile_id) is not None
