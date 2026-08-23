"""
Predefined NSE Script Manager
==============================
Maintains allowlisted NSE scripts, maps detected services to scripts,
and executes information-gathering scripts using secure subprocess calls.
"""

import os
import subprocess
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional
from datetime import datetime

from models import db, Scan, Host, Port, NSEResult
from services.nmap_service import check_nmap_availability

logger = logging.getLogger(__name__)

# Predefined allowable NSE profiles mapping
NSE_PROFILES: Dict[str, List[str]] = {
    "http": ["http-title", "http-headers"],
    "ssh": ["ssh2-enum-algos"]
}

# Approved scripts registry with metadata
NSE_SCRIPTS_LIBRARY: Dict[str, Dict[str, Any]] = {
    "http-title": {
        "script_id": "http-title",
        "service": "HTTP/HTTPS",
        "description": "Retrieves the title of an HTTP web service.",
        "category": "Information Gathering",
        "severity": "info",
        "risk": "Low"
    },
    "http-headers": {
        "script_id": "http-headers",
        "service": "HTTP/HTTPS",
        "description": "Retrieves HTTP response headers.",
        "category": "Information Gathering",
        "severity": "info",
        "risk": "Low"
    },
    "ssh2-enum-algos": {
        "script_id": "ssh2-enum-algos",
        "service": "SSH",
        "description": "Enumerates supported cryptographic key exchange algorithms and ciphers on the SSH server.",
        "category": "Information Gathering",
        "severity": "info",
        "risk": "Low"
    }
}

def execute_nse_scripts_for_scan(scan_id: int, app) -> bool:
    """
    Executes relevant allowlisted NSE scripts based on detected open services.
    Enforces authentication & authorization check at callers, and runs in the background/foreground.
    """
    with app.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan:
            logger.error(f"NSE Execution failed: Scan #{scan_id} does not exist.")
            return False

        logger.info(f"Starting Predefined NSE Script Analysis for Scan #{scan_id}...")

        # 1. Clean existing NSE results for this scan to prevent duplication
        NSEResult.query.filter_by(scan_id=scan_id).delete(synchronize_session=False)
        db.session.commit()

        hosts = Host.query.filter_by(scan_id=scan_id).all()
        if not hosts:
            logger.info(f"NSE Execution: No hosts found for Scan #{scan_id}.")
            return True

        nmap_check = check_nmap_availability(app.config.get('NMAP_PATH', 'nmap'))
        nse_timeout = 30  # Max seconds per script execution to prevent hanging

        for host in hosts:
            # Map detected services on this host
            ports = Port.query.filter_by(host_id=host.id, state='open').all()
            
            # Keep track of which scripts are run to mark others as skipped
            executed_scripts = set()

            for port in ports:
                service_name = (port.service or '').lower().strip()
                applicable_scripts = []

                if service_name in ('http', 'https', 'ssl/http', 'http-ssl', 'http-alt', 'https-alt'):
                    applicable_scripts = NSE_PROFILES["http"]
                elif service_name == 'ssh':
                    applicable_scripts = NSE_PROFILES["ssh"]
                # Additional mapping by port fallback if service is unknown but port is standard
                elif port.port_number in (80, 8080, 3128):
                    applicable_scripts = NSE_PROFILES["http"]
                    port.service = 'http'  # update service name for visual consistency
                elif port.port_number in (443, 8443):
                    applicable_scripts = NSE_PROFILES["http"]
                    port.service = 'https'
                elif port.port_number == 22:
                    applicable_scripts = NSE_PROFILES["ssh"]
                    port.service = 'ssh'

                for script_id in applicable_scripts:
                    executed_scripts.add(script_id)
                    script_meta = NSE_SCRIPTS_LIBRARY[script_id]

                    # Create initial Pending result
                    result_record = NSEResult(
                        scan_id=scan.id,
                        host_id=host.id,
                        script_id=script_id,
                        service=port.service,
                        port_number=port.port_number,
                        description=script_meta["description"],
                        severity=script_meta["severity"],
                        status="Running"
                    )
                    db.session.add(result_record)
                    db.session.commit()

                    if nmap_check['available']:
                        # Live Nmap NSE execution
                        xml_output_file = os.path.join(app.config['SCANS_FOLDER'], str(scan_id), f"nse_{host.id}_{port.port_number}_{script_id}.xml")
                        try:
                            # Construct safe arguments: nmap -p <port> --script <script> -oX <file> <target>
                            cmd = [
                                nmap_check['path'],
                                '-p', str(port.port_number),
                                f'--script={script_id}',
                                '-oX', xml_output_file,
                                host.ip_address
                            ]
                            logger.info(f"Executing live NSE: {' '.join(cmd[:4])} against target {host.ip_address}")
                            
                            proc = subprocess.run(cmd, capture_output=True, timeout=nse_timeout, shell=False)
                            
                            if proc.returncode == 0 and os.path.exists(xml_output_file):
                                # Parse the XML
                                script_output = _parse_script_xml_output(xml_output_file, script_id)
                                if script_output:
                                    result_record.output = script_output
                                    result_record.status = "Completed"
                                else:
                                    result_record.output = "Script completed but returned empty output."
                                    result_record.status = "Completed"
                            else:
                                result_record.status = "Failed"
                                result_record.error_message = f"Nmap exited with code {proc.returncode}"
                                result_record.output = "Execution failed."
                        except subprocess.TimeoutExpired:
                            logger.warning(f"NSE script {script_id} timed out on {host.ip_address}:{port.port_number}")
                            result_record.status = "Failed"
                            result_record.error_message = "NSE execution timed out."
                            result_record.output = "Timeout expired."
                        except Exception as ex:
                            logger.error(f"Error running NSE script {script_id}: {str(ex)}")
                            result_record.status = "Failed"
                            result_record.error_message = f"Error: {str(ex)}"
                            result_record.output = "Execution error."
                        finally:
                            # Cleanup temporary XML file if created
                            if os.path.exists(xml_output_file):
                                try:
                                    os.remove(xml_output_file)
                                except:
                                    pass
                    else:
                        # Simulation Mode
                        script_output = _get_simulated_script_output(script_id, port.port_number, host.ip_address)
                        result_record.output = script_output
                        result_record.status = "Completed"
                    
                    db.session.commit()

            # Record all other allowlisted scripts as Skipped (since their corresponding service was not detected)
            for script_id, script_meta in NSE_SCRIPTS_LIBRARY.items():
                if script_id not in executed_scripts:
                    skipped_record = NSEResult(
                        scan_id=scan.id,
                        host_id=host.id,
                        script_id=script_id,
                        service=script_meta["service"],
                        port_number=None,
                        description=script_meta["description"],
                        severity=script_meta["severity"],
                        status="Skipped",
                        output="Skipped",
                        error_message="Required service was not detected."
                    )
                    db.session.add(skipped_record)

            db.session.commit()

        logger.info(f"NSE Script Analysis completed for Scan #{scan_id}")
        return True

def _parse_script_xml_output(xml_path: str, script_id: str) -> Optional[str]:
    """
    Parses Nmap XML output file to extract the text output of a specific script ID.
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host_el in root.findall('host'):
            ports_el = host_el.find('ports')
            if ports_el is not None:
                for port_el in ports_el.findall('port'):
                    for script_el in port_el.findall('script'):
                        if script_el.attrib.get('id') == script_id:
                            return script_el.attrib.get('output', '')
    except Exception as ex:
        logger.error(f"Error parsing NSE script XML output: {str(ex)}")
    return None

def _get_simulated_script_output(script_id: str, port_number: int, target: str) -> str:
    """
    Returns realistic predefined outputs for educational lab validation.
    """
    if script_id == "http-title":
        if port_number == 443:
            return "VulnApp Secure Portal"
        return "VulnApp Laboratory Landing Page"
    
    if script_id == "http-headers":
        return (
            "HTTP/1.1 200 OK\n"
            "Date: Thu, 20 Aug 2026 17:30:00 GMT\n"
            f"Server: Apache/2.4.58 (Ubuntu)\n"
            "Last-Modified: Sun, 10 May 2026 09:15:20 GMT\n"
            "X-Frame-Options: SAMEORIGIN\n"
            "X-Content-Type-Options: nosniff\n"
            "Connection: close\n"
            "Content-Type: text/html; charset=UTF-8"
        )
        
    if script_id == "ssh2-enum-algos":
        return (
            "  kex_algorithms: (9)\n"
            "    curve25519-sha256\n"
            "    curve25519-sha256@libssh.org\n"
            "    ecdh-sha2-nistp256\n"
            "    ecdh-sha2-nistp384\n"
            "    ecdh-sha2-nistp521\n"
            "  server_host_key_algorithms: (5)\n"
            "    rsa-sha2-512\n"
            "    rsa-sha2-256\n"
            "    ecdsa-sha2-nistp256\n"
            "    ssh-ed25519\n"
            "    ssh-rsa\n"
            "  encryption_algorithms: (6)\n"
            "    chacha20-poly1305@openssh.com\n"
            "    aes128-ctr\n"
            "    aes256-ctr\n"
            "  mac_algorithms: (4)\n"
            "    umac-64-etm@openssh.com\n"
            "    umac-128-etm@openssh.com\n"
            "    hmac-sha2-256\n"
            "    hmac-sha2-512"
        )

    return "Predefined simulation output."
