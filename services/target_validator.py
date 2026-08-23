"""
Target Validation & Safety Boundary Service
============================================
Provides strict input validation, normalization, injection prevention, and
authorization checks for educational network scanning in laboratory environments.
"""

import ipaddress
import re
from typing import Dict, Any, Optional, List

# Strict RFC 1123 Hostname regex (supports single labels like 'localhost' or dotted labels like 'lab-server.local')
HOSTNAME_REGEX = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$'
)

# Forbidden shell metacharacters and control characters
SHELL_METACHAR_REGEX = re.compile(r'[;&|\$`><\\(){}\*?!\[\]\n\r\t]')

def validate_target(
    target: Optional[str],
    authorized_targets: Optional[List[str]] = None,
    allow_private_subnets: bool = True,
    allow_localhost: bool = True
) -> Dict[str, Any]:
    """
    Validates, normalizes, and enforces safety boundaries on a scan target.

    Args:
        target: The raw target string provided by user.
        authorized_targets: Optional list of explicitly permitted targets (IPs or hostnames).
        allow_private_subnets: Whether RFC 1918 private subnets are permitted (default True).
        allow_localhost: Whether loopback addresses are permitted (default True).

    Returns:
        Dict containing:
            - valid (bool): Whether the target has a valid syntax and no malicious patterns.
            - target (str): The normalized target string.
            - type (str or None): 'PRIVATE', 'PUBLIC', 'LOOPBACK', 'HOSTNAME', or None.
            - authorized (bool): Whether the target is within the permitted boundaries.
            - message (str): Human-readable feedback message.
    """
    if target is None or not isinstance(target, str):
        return {
            "valid": False,
            "target": "",
            "type": None,
            "authorized": False,
            "message": "Please enter a target."
        }

    # Step 1: Normalization
    normalized = target.strip()
    if not normalized:
        return {
            "valid": False,
            "target": "",
            "type": None,
            "authorized": False,
            "message": "Please enter a target."
        }

    # Step 2: Malicious Input & Command Injection Protection
    if any(c.isspace() for c in normalized):
        return {
            "valid": False,
            "target": normalized,
            "type": None,
            "authorized": False,
            "message": "Invalid target format."
        }

    if SHELL_METACHAR_REGEX.search(normalized):
        return {
            "valid": False,
            "target": normalized,
            "type": None,
            "authorized": False,
            "message": "Invalid target format."
        }

    if normalized.startswith('-') or normalized.startswith('/'):
        return {
            "valid": False,
            "target": normalized,
            "type": None,
            "authorized": False,
            "message": "Invalid target format."
        }

    auth_set = set()
    if authorized_targets:
        for t in authorized_targets:
            if isinstance(t, str):
                auth_set.add(t.strip().lower())

    # Helper function to classify and authorize IP address
    def _evaluate_ip(ip_obj, canonical_ip) -> Dict[str, Any]:
        if canonical_ip.lower() in auth_set:
            if ip_obj.is_loopback:
                t_type = "LOOPBACK"
            elif ip_obj.is_private or ip_obj.is_link_local:
                t_type = "PRIVATE"
            else:
                t_type = "PUBLIC"
            return {
                "valid": True,
                "target": canonical_ip,
                "type": t_type,
                "authorized": True,
                "message": "Target is authorized and ready for scanning."
            }

        if ip_obj.is_loopback:
            t_type = "LOOPBACK"
            authorized = allow_localhost
            msg = "Target is authorized and ready for scanning." if authorized else "Target is outside the configured authorized laboratory boundary."
        elif ip_obj.is_private or ip_obj.is_link_local:
            t_type = "PRIVATE"
            authorized = allow_private_subnets
            msg = "Target is authorized and ready for scanning." if authorized else "Target is outside the configured authorized laboratory boundary."
        else:
            t_type = "PUBLIC"
            authorized = False
            msg = "Target requires explicit authorization."

        return {
            "valid": True,
            "target": canonical_ip,
            "type": t_type,
            "authorized": authorized,
            "message": msg
        }

    # Step 3: Check IPv4
    try:
        ip_obj = ipaddress.IPv4Address(normalized)
        return _evaluate_ip(ip_obj, str(ip_obj))
    except (ipaddress.AddressValueError, ValueError):
        pass

    # Step 4: Check IPv6
    try:
        ip6_obj = ipaddress.IPv6Address(normalized)
        return _evaluate_ip(ip6_obj, str(ip6_obj))
    except (ipaddress.AddressValueError, ValueError):
        pass

    # Step 5: Check Hostname
    lower_hostname = normalized.lower()
    if len(lower_hostname) > 253 or not HOSTNAME_REGEX.match(lower_hostname):
        return {
            "valid": False,
            "target": normalized,
            "type": None,
            "authorized": False,
            "message": "Target format is invalid."
        }

    if all(part.isdigit() for part in lower_hostname.split('.')):
        return {
            "valid": False,
            "target": normalized,
            "type": None,
            "authorized": False,
            "message": "Target format is invalid."
        }

    if lower_hostname in auth_set:
        return {
            "valid": True,
            "target": lower_hostname,
            "type": "HOSTNAME",
            "authorized": True,
            "message": "Target is authorized and ready for scanning."
        }

    if lower_hostname == 'localhost':
        authorized = allow_localhost
        return {
            "valid": True,
            "target": 'localhost',
            "type": "HOSTNAME",
            "authorized": authorized,
            "message": "Target is authorized and ready for scanning." if authorized else "Target is outside the configured authorized laboratory boundary."
        }

    if any(lower_hostname.endswith(suffix) for suffix in ('.local', '.lab', '.internal', '.lan')):
        if allow_private_subnets:
            return {
                "valid": True,
                "target": lower_hostname,
                "type": "HOSTNAME",
                "authorized": True,
                "message": "Target is authorized and ready for scanning."
            }

    return {
        "valid": True,
        "target": lower_hostname,
        "type": "HOSTNAME",
        "authorized": False,
        "message": "Target requires explicit authorization."
    }
