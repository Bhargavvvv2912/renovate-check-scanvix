"""
Rule-Based Findings Analyzer Engine
====================================
Deterministic, explainable security observations parser. Parses scan details
and generates structured findings based on centralized policy rules.
"""

import logging
from datetime import datetime
from typing import Dict, Any, List, Optional

from models import db, Scan, Host, Port, NSEResult, Finding
from services.finding_rules import FINDING_RULES

logger = logging.getLogger(__name__)

def analyze_scan_results(scan_id: int, app) -> bool:
    """
    Evaluates scan target results against finding rules.
    Generates, deduplicates, and persists observations in SQLite.
    """
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan:
            logger.error(f"Analysis failed: Scan #{scan_id} not found.")
            return False

        logger.info(f"Finding analysis started for scan #{scan_id}")

        # 1. Clean existing findings for this scan to prevent stale duplicates
        Finding.query.filter_by(scan_id=scan_id).delete(synchronize_session=False)
        db.session.commit()

        hosts = Host.query.filter_by(scan_id=scan_id).all()
        if not hosts:
            logger.info(f"No hosts observed for Scan #{scan_id}. Analysis completed.")
            scan.number_of_findings = 0
            db.session.commit()
            return True

        findings_to_add = []
        # Deduplication key tracker: (rule_id, host_id, port_id)
        seen_findings = set()

        for host in hosts:
            open_ports = Port.query.filter_by(host_id=host.id, state='open').all()

            for port in open_ports:
                service_name = (port.service or '').lower().strip()
                port_num = port.port_number

                # Common details for evidence formatting
                evidence_header = (
                    f"Host Target: {host.ip_address}\n"
                    f"Port: {port_num}/{port.protocol}\n"
                    f"State: {port.state}\n"
                    f"Service: {port.service or 'unknown'}\n"
                    f"Product: {port.product or '—'}\n"
                    f"Version: {port.version or '—'}"
                )

                # ============================================================
                # RULE: NMAP-OBS-001 (Open Network Service Observed) - Always triggers
                # ============================================================
                rule_id = "NMAP-OBS-001"
                dedup_key = (rule_id, host.id, port.id)
                if dedup_key not in seen_findings:
                    seen_findings.add(dedup_key)
                    rule = FINDING_RULES[rule_id]
                    
                    finding = Finding(
                        scan_id=scan.id,
                        host_id=host.id,
                        port_id=port.id,
                        rule_id=rule_id,
                        category=rule["category"],
                        title=rule["title"],
                        severity=rule["severity"],
                        description=rule["description"],
                        evidence=evidence_header,
                        remediation=rule["remediation"],
                        recommendation=rule["remediation"],  # align to legacy column name
                        classification=rule["observation_type"],  # align to legacy column name
                        confidence=rule["confidence"],
                        observation_type=rule["observation_type"],
                        status="OPEN",
                        created_at=datetime.utcnow()
                    )
                    findings_to_add.append(finding)

                # ============================================================
                # RULE: NMAP-HTTP-001 (Potential Cleartext HTTP)
                # ============================================================
                if service_name == 'http' or port_num == 80:
                    rule_id = "NMAP-HTTP-001"
                    dedup_key = (rule_id, host.id, port.id)
                    if dedup_key not in seen_findings:
                        seen_findings.add(dedup_key)
                        rule = FINDING_RULES[rule_id]
                        
                        evidence = f"{evidence_header}\nObserved HTTP protocol without TLS headers."
                        
                        finding = Finding(
                            scan_id=scan.id,
                            host_id=host.id,
                            port_id=port.id,
                            rule_id=rule_id,
                            category=rule["category"],
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            evidence=evidence,
                            remediation=rule["remediation"],
                            recommendation=rule["remediation"],
                            classification=rule["observation_type"],
                            confidence=rule["confidence"],
                            observation_type=rule["observation_type"],
                            status="OPEN",
                            created_at=datetime.utcnow()
                        )
                        findings_to_add.append(finding)

                # ============================================================
                # RULE: NMAP-FTP-001 (Potential Cleartext FTP Protocol)
                # ============================================================
                if service_name == 'ftp' or port_num == 21:
                    rule_id = "NMAP-FTP-001"
                    dedup_key = (rule_id, host.id, port.id)
                    if dedup_key not in seen_findings:
                        seen_findings.add(dedup_key)
                        rule = FINDING_RULES[rule_id]
                        
                        evidence = f"{evidence_header}\nObserved listening FTP control channel."
                        
                        finding = Finding(
                            scan_id=scan.id,
                            host_id=host.id,
                            port_id=port.id,
                            rule_id=rule_id,
                            category=rule["category"],
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            evidence=evidence,
                            remediation=rule["remediation"],
                            recommendation=rule["remediation"],
                            classification=rule["observation_type"],
                            confidence=rule["confidence"],
                            observation_type=rule["observation_type"],
                            status="OPEN",
                            created_at=datetime.utcnow()
                        )
                        findings_to_add.append(finding)

                # ============================================================
                # RULE: NMAP-TELNET-001 (Unencrypted Telnet Administration)
                # ============================================================
                if service_name == 'telnet' or port_num == 23:
                    rule_id = "NMAP-TELNET-001"
                    dedup_key = (rule_id, host.id, port.id)
                    if dedup_key not in seen_findings:
                        seen_findings.add(dedup_key)
                        rule = FINDING_RULES[rule_id]
                        
                        evidence = f"{evidence_header}\nTelnet service listening on standard port."
                        
                        finding = Finding(
                            scan_id=scan.id,
                            host_id=host.id,
                            port_id=port.id,
                            rule_id=rule_id,
                            category=rule["category"],
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            evidence=evidence,
                            remediation=rule["remediation"],
                            recommendation=rule["remediation"],
                            classification=rule["observation_type"],
                            confidence=rule["confidence"],
                            observation_type=rule["observation_type"],
                            status="OPEN",
                            created_at=datetime.utcnow()
                        )
                        findings_to_add.append(finding)

                # ============================================================
                # RULE: NMAP-SSH-001 (SSH Service Discovered)
                # ============================================================
                if service_name == 'ssh' or port_num == 22:
                    rule_id = "NMAP-SSH-001"
                    dedup_key = (rule_id, host.id, port.id)
                    if dedup_key not in seen_findings:
                        seen_findings.add(dedup_key)
                        rule = FINDING_RULES[rule_id]
                        
                        evidence = f"{evidence_header}\nSSH server detected."
                        
                        finding = Finding(
                            scan_id=scan.id,
                            host_id=host.id,
                            port_id=port.id,
                            rule_id=rule_id,
                            category=rule["category"],
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            evidence=evidence,
                            remediation=rule["remediation"],
                            recommendation=rule["remediation"],
                            classification=rule["observation_type"],
                            confidence=rule["confidence"],
                            observation_type=rule["observation_type"],
                            status="OPEN",
                            created_at=datetime.utcnow()
                        )
                        findings_to_add.append(finding)

                    # ============================================================
                    # RULE: NMAP-SSH-002 (Weak SSH Cryptographic Configuration)
                    # ============================================================
                    # Query for script result
                    nse = NSEResult.query.filter_by(
                        scan_id=scan.id, 
                        host_id=host.id, 
                        script_id='ssh2-enum-algos'
                    ).first()
                    
                    if nse and nse.output:
                        out_lower = nse.output.lower()
                        weak_tokens = ['cbc', '3des', 'rc4', 'blowfish', 'hmac-sha1', 'hmac-md5']
                        found_weak = [tk for tk in weak_tokens if tk in out_lower]
                        
                        if found_weak:
                            rule_id = "NMAP-SSH-002"
                            dedup_key = (rule_id, host.id, port.id)
                            if dedup_key not in seen_findings:
                                seen_findings.add(dedup_key)
                                rule = FINDING_RULES[rule_id]
                                
                                evidence = (
                                    f"Host: {host.ip_address}:{port_num}\n"
                                    f"Script ID: ssh2-enum-algos\n"
                                    f"Observed Weak Cryptographic Elements: {', '.join(found_weak)}\n\n"
                                    f"NSE Script Output Snippet:\n{nse.output[:300]}"
                                )
                                
                                finding = Finding(
                                    scan_id=scan.id,
                                    host_id=host.id,
                                    port_id=port.id,
                                    rule_id=rule_id,
                                    category=rule["category"],
                                    title=rule["title"],
                                    severity=rule["severity"],
                                    description=rule["description"],
                                    evidence=evidence,
                                    remediation=rule["remediation"],
                                    recommendation=rule["remediation"],
                                    classification=rule["observation_type"],
                                    confidence=rule["confidence"],
                                    observation_type=rule["observation_type"],
                                    status="OPEN",
                                    created_at=datetime.utcnow()
                                )
                                findings_to_add.append(finding)

                # ============================================================
                # RULE: NMAP-DB-001 (Exposed Database Service)
                # ============================================================
                if service_name in ('mysql', 'postgresql', 'redis', 'mongodb', 'oracle', 'mssql') or port_num in (3306, 5432, 6379, 27017, 1433, 1521):
                    rule_id = "NMAP-DB-001"
                    dedup_key = (rule_id, host.id, port.id)
                    if dedup_key not in seen_findings:
                        seen_findings.add(dedup_key)
                        rule = FINDING_RULES[rule_id]
                        
                        evidence = f"{evidence_header}\nActive database service observed responding to network queries."
                        
                        finding = Finding(
                            scan_id=scan.id,
                            host_id=host.id,
                            port_id=port.id,
                            rule_id=rule_id,
                            category=rule["category"],
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            evidence=evidence,
                            remediation=rule["remediation"],
                            recommendation=rule["remediation"],
                            classification=rule["observation_type"],
                            confidence=rule["confidence"],
                            observation_type=rule["observation_type"],
                            status="OPEN",
                            created_at=datetime.utcnow()
                        )
                        findings_to_add.append(finding)

                # ============================================================
                # RULE: NMAP-RDP-001 (Remote Desktop Protocol Exposed)
                # ============================================================
                if service_name == 'ms-wbt-server' or port_num == 3389:
                    rule_id = "NMAP-RDP-001"
                    dedup_key = (rule_id, host.id, port.id)
                    if dedup_key not in seen_findings:
                        seen_findings.add(dedup_key)
                        rule = FINDING_RULES[rule_id]
                        
                        evidence = f"{evidence_header}\nRemote Desktop Protocol service listening."
                        
                        finding = Finding(
                            scan_id=scan.id,
                            host_id=host.id,
                            port_id=port.id,
                            rule_id=rule_id,
                            category=rule["category"],
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            evidence=evidence,
                            remediation=rule["remediation"],
                            recommendation=rule["remediation"],
                            classification=rule["observation_type"],
                            confidence=rule["confidence"],
                            observation_type=rule["observation_type"],
                            status="OPEN",
                            created_at=datetime.utcnow()
                        )
                        findings_to_add.append(finding)

                # ============================================================
                # RULE: NMAP-VERSION-001 (Software Version Information Disclosed)
                # ============================================================
                if port.product or port.version:
                    rule_id = "NMAP-VERSION-001"
                    dedup_key = (rule_id, host.id, port.id)
                    if dedup_key not in seen_findings:
                        seen_findings.add(dedup_key)
                        rule = FINDING_RULES[rule_id]
                        
                        evidence = (
                            f"Host: {host.ip_address}\n"
                            f"Service: {port.service or 'unknown'} on port {port_num}\n"
                            f"Banner Disclosed Product: {port.product or '—'}\n"
                            f"Banner Disclosed Version: {port.version or '—'}"
                        )
                        
                        finding = Finding(
                            scan_id=scan.id,
                            host_id=host.id,
                            port_id=port.id,
                            rule_id=rule_id,
                            category=rule["category"],
                            title=rule["title"],
                            severity=rule["severity"],
                            description=rule["description"],
                            evidence=evidence,
                            remediation=rule["remediation"],
                            recommendation=rule["remediation"],
                            classification=rule["observation_type"],
                            confidence=rule["confidence"],
                            observation_type=rule["observation_type"],
                            status="OPEN",
                            created_at=datetime.utcnow()
                        )
                        findings_to_add.append(finding)

        # 2. Add all unique findings securely
        if findings_to_add:
            db.session.add_all(findings_to_add)
            db.session.commit()

        # Update Scan metadata count
        scan.number_of_findings = len(findings_to_add)
        db.session.commit()

        logger.info(f"Generated {len(findings_to_add)} findings for scan #{scan_id}")
        logger.info("Finding analysis completed successfully.")
        return True
