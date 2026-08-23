"""
Predefined Finding Rules Registry
===================================
Centralized catalog of explainable, deterministic finding rules.
"""

from typing import Dict, Any, List

FINDING_RULES: Dict[str, Dict[str, Any]] = {
    "NMAP-OBS-001": {
        "rule_id": "NMAP-OBS-001",
        "title": "Open Network Service Observed",
        "severity": "INFO",
        "category": "Service Exposure",
        "confidence": "HIGH",
        "observation_type": "OBSERVED",
        "description": "An open listening port and active network service was discovered during network scanning.",
        "remediation": "Review whether this service is required and ensure it is intentionally exposed within the authorized environment."
    },
    "NMAP-HTTP-001": {
        "rule_id": "NMAP-HTTP-001",
        "title": "Potential Cleartext HTTP Protocol",
        "severity": "LOW",
        "category": "Encryption",
        "confidence": "MEDIUM",
        "observation_type": "POTENTIAL",
        "description": "The detected HTTP service transmits application traffic in cleartext without transport-layer encryption.",
        "remediation": "Use HTTPS for sensitive application traffic and configure appropriate TLS settings."
    },
    "NMAP-FTP-001": {
        "rule_id": "NMAP-FTP-001",
        "title": "Potential Cleartext FTP Protocol",
        "severity": "LOW",
        "category": "Protocol Security",
        "confidence": "MEDIUM",
        "observation_type": "POTENTIAL",
        "description": "FTP commonly transmits session credentials and data in cleartext without transport encryption.",
        "remediation": "Disable cleartext FTP. Configure FTPS (FTP over SSL/TLS) or migrate to SFTP (SSH File Transfer Protocol on port 22)."
    },
    "NMAP-TELNET-001": {
        "rule_id": "NMAP-TELNET-001",
        "title": "Unencrypted Telnet Administration",
        "severity": "MEDIUM",
        "category": "Protocol Security",
        "confidence": "HIGH",
        "observation_type": "POTENTIAL",
        "description": "Telnet is an insecure legacy protocol that lacks cryptographic transport, exposing remote management traffic and credentials.",
        "remediation": "Migrate to SSH or another secure remote administration protocol."
    },
    "NMAP-SSH-001": {
        "rule_id": "NMAP-SSH-001",
        "title": "SSH Service Discovered",
        "severity": "INFO",
        "category": "SSH Security",
        "confidence": "HIGH",
        "observation_type": "OBSERVED",
        "description": "An SSH remote command-line administration service was detected on the target host.",
        "remediation": "Ensure the SSH server is configured to use strong key-based authentication and disable root password logons."
    },
    "NMAP-SSH-002": {
        "rule_id": "NMAP-SSH-002",
        "title": "Weak SSH Cryptographic Configuration",
        "severity": "LOW",
        "category": "SSH Security",
        "confidence": "HIGH",
        "observation_type": "POTENTIAL",
        "description": "The remote SSH server supports outdated, obsolete, or cryptographically weak key exchange algorithms, ciphers, or MAC algorithms.",
        "remediation": "Review the SSH server configuration (e.g., sshd_config) and disable legacy algorithms. Enforce curve25519-sha256, diffie-hellman-group16-sha512, and AES-GCM ciphers."
    },
    "NMAP-DB-001": {
        "rule_id": "NMAP-DB-001",
        "title": "Exposed Database Service",
        "severity": "LOW",
        "category": "Network Security",
        "confidence": "HIGH",
        "observation_type": "OBSERVED",
        "description": "A database server is listening and accessible via a network port.",
        "remediation": "Restrict database access to localhost or authorized server IP addresses only. Implement strict firewall rules and transport-layer encryption (SSL/TLS)."
    },
    "NMAP-RDP-001": {
        "rule_id": "NMAP-RDP-001",
        "title": "Remote Desktop Protocol Exposed",
        "severity": "LOW",
        "category": "Network Security",
        "confidence": "HIGH",
        "observation_type": "OBSERVED",
        "description": "Remote Desktop Protocol (RDP) remote access service was observed listening on the target host.",
        "remediation": "Verify if external access is necessary. Enforce Network Level Authentication (NLA) and restrict connection sources via IP filters or a secure VPN."
    },
    "NMAP-VERSION-001": {
        "rule_id": "NMAP-VERSION-001",
        "title": "Software Version Information Disclosed",
        "severity": "INFO",
        "category": "Information Disclosure",
        "confidence": "HIGH",
        "observation_type": "OBSERVED",
        "description": "The remote service discloses application name and version banners, assisting external reconnaissance.",
        "remediation": "Restrict banner disclosure in configuration settings where supported (e.g. ServerTokens ProductOnly for Apache) or omit detailed versions."
    }
}
