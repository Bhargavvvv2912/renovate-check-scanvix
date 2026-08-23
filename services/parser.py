"""
NMAP XML Parsing Engine & Data Model Integration
=================================================
Validates, extracts, and securely persists structured host, port, service,
OS detection, and NSE script metadata from Phase 5 Nmap XML outputs.
"""

import os
import logging
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Optional, Union

from models import db, Scan, Host, Port, NSEResult

logger = logging.getLogger(__name__)

# Maximum allowed XML file size (10 MB)
MAX_XML_FILE_SIZE = 10 * 1024 * 1024

class XMLParserError(Exception):
    """Base exception for XML parsing failures."""
    pass

class XMLSecurityError(XMLParserError):
    """Raised when XML path or file security validations fail."""
    pass

class InvalidNmapXMLError(XMLParserError):
    """Raised when XML document is malformed or not standard Nmap XML."""
    pass

def validate_xml_file(xml_path: str, allowed_base_dir: Optional[str] = None) -> str:
    """
    Validates XML file existence, path canonicalization, traversal safety, and file size.
    Returns canonicalized absolute file path.
    """
    if not xml_path or not isinstance(xml_path, str):
        raise XMLSecurityError("A valid XML filepath must be provided.")

    abs_path = os.path.abspath(xml_path)

    # Check path traversal if allowed_base_dir is specified
    if allowed_base_dir:
        abs_base = os.path.abspath(allowed_base_dir)
        try:
            common = os.path.commonpath([abs_base, abs_path])
            if common != abs_base:
                raise XMLSecurityError(f"Access denied: XML path '{abs_path}' is outside designated storage '{abs_base}'.")
        except ValueError:
            raise XMLSecurityError(f"Access denied: XML path '{abs_path}' is outside designated storage '{abs_base}'.")

    if not os.path.exists(abs_path):
        raise XMLSecurityError(f"XML output file not found at: {abs_path}")

    if not os.path.isfile(abs_path):
        raise XMLSecurityError(f"Specified path is not a regular file: {abs_path}")

    file_size = os.path.getsize(abs_path)
    if file_size > MAX_XML_FILE_SIZE:
        raise XMLSecurityError(f"XML file size ({file_size} bytes) exceeds limit of {MAX_XML_FILE_SIZE} bytes.")

    return abs_path

def parse_nmap_xml(xml_source: Union[str, bytes]) -> Dict[str, Any]:
    """
    Parses Nmap XML from file path or raw XML bytes/string.
    Extracts hosts, addresses, hostnames, host states, OS detections,
    ports, protocols, port states, service details, and NSE script outputs.
    """
    try:
        if isinstance(xml_source, str) and os.path.exists(xml_source):
            tree = ET.parse(xml_source)
            root = tree.getroot()
        elif isinstance(xml_source, (str, bytes)):
            root = ET.fromstring(xml_source)
        else:
            raise InvalidNmapXMLError("Invalid Nmap XML output.")
    except ET.ParseError as pe:
        logger.error(f"XML Syntax Parse Error: {str(pe)}")
        raise InvalidNmapXMLError(f"Invalid Nmap XML output: {str(pe)}")
    except Exception as e:
        logger.error(f"XML Loading Error: {str(e)}")
        if isinstance(e, XMLParserError):
            raise
        raise InvalidNmapXMLError(f"Invalid Nmap XML output: {str(e)}")

    # Verify Root Element is <nmaprun>
    tag_name = root.tag.split('}')[-1] if '}' in root.tag else root.tag
    if tag_name.lower() != 'nmaprun':
        raise InvalidNmapXMLError(f"Invalid Nmap XML output.")

    scanner = root.attrib.get('scanner', 'nmap')
    version = root.attrib.get('version', '')
    args = root.attrib.get('args', '')

    parsed_hosts: List[Dict[str, Any]] = []
    total_open_ports = 0

    for host_el in root.findall('host'):
        # 1. Host State
        status_el = host_el.find('status')
        host_state = status_el.attrib.get('state', 'up') if status_el is not None else 'up'

        # 2. IP Address (IPv4 or IPv6)
        ip_address = None
        for addr_el in host_el.findall('address'):
            addr = addr_el.attrib.get('addr')
            addr_type = addr_el.attrib.get('addrtype', 'ipv4')
            if addr and addr_type in ('ipv4', 'ipv6'):
                ip_address = addr
                if addr_type == 'ipv4':  # Prefer IPv4 if available
                    break

        if not ip_address:
            # Check fallback address
            fallback_addr = host_el.find('address')
            if fallback_addr is not None:
                ip_address = fallback_addr.attrib.get('addr')

        if not ip_address:
            ip_address = 'unknown'

        # 3. Hostname
        hostname = None
        hostnames_el = host_el.find('hostnames')
        if hostnames_el is not None:
            first_h = hostnames_el.find('hostname')
            if first_h is not None:
                hostname = first_h.attrib.get('name')

        # 4. OS Information
        os_info = None
        os_el = host_el.find('os')
        if os_el is not None:
            osmatch_el = os_el.find('osmatch')
            if osmatch_el is not None:
                os_name = osmatch_el.attrib.get('name', '')
                os_accuracy = osmatch_el.attrib.get('accuracy', '')
                os_info = f"{os_name} ({os_accuracy}%)" if os_accuracy else os_name

        # 5. Ports & Services
        parsed_ports: List[Dict[str, Any]] = []
        host_scripts: List[Dict[str, Any]] = []

        ports_container = host_el.find('ports')
        if ports_container is not None:
            for port_el in ports_container.findall('port'):
                port_id_raw = port_el.attrib.get('portid')
                if not port_id_raw or not port_id_raw.isdigit():
                    continue

                port_number = int(port_id_raw)
                protocol = port_el.attrib.get('protocol', 'tcp')

                # Port State
                state_el = port_el.find('state')
                port_state = state_el.attrib.get('state', 'unknown') if state_el is not None else 'unknown'
                if port_state.lower() == 'open':
                    total_open_ports += 1

                # Service Details
                service_name = None
                product = None
                service_version = None
                extra_info = None

                service_el = port_el.find('service')
                if service_el is not None:
                    service_name = service_el.attrib.get('name')
                    product = service_el.attrib.get('product')
                    service_version = service_el.attrib.get('version')
                    extra_info = service_el.attrib.get('extrainfo')

                parsed_ports.append({
                    'port_number': port_number,
                    'protocol': protocol,
                    'state': port_state,
                    'service': service_name,
                    'product': product,
                    'version': service_version,
                    'extra_info': extra_info
                })

                # Port-level NSE Scripts
                for script_el in port_el.findall('script'):
                    s_id = script_el.attrib.get('id')
                    s_output = script_el.attrib.get('output', '')
                    if s_id:
                        host_scripts.append({
                            'script_id': s_id,
                            'output': s_output,
                            'service': service_name or f"{port_number}/{protocol}",
                            'port_number': port_number
                        })

        # 6. Host-level Scripts (<hostscript>)
        hostscript_el = host_el.find('hostscript')
        if hostscript_el is not None:
            for script_el in hostscript_el.findall('script'):
                s_id = script_el.attrib.get('id')
                s_output = script_el.attrib.get('output', '')
                if s_id:
                    host_scripts.append({
                        'script_id': s_id,
                        'output': s_output,
                        'service': 'host-script',
                        'port_number': None
                    })

        parsed_hosts.append({
            'ip_address': ip_address,
            'hostname': hostname,
            'state': host_state,
            'os_information': os_info,
            'ports': parsed_ports,
            'scripts': host_scripts
        })

    return {
        'scanner': scanner,
        'version': version,
        'args': args,
        'hosts': parsed_hosts,
        'total_hosts': len(parsed_hosts),
        'open_ports_count': total_open_ports
    }

def store_parsed_scan_results(scan_id: int, parsed_data: Dict[str, Any], session=None) -> Scan:
    """
    Persists parsed host, port, and NSE result entities into SQLite via SQLAlchemy.
    Uses atomic transaction and eliminates duplicate records if reparsing.
    """
    active_session = session or db.session

    scan = active_session.get(Scan, scan_id)
    if not scan:
        raise XMLParserError(f"Target Scan record #{scan_id} does not exist in database.")

    try:
        # 1. Clean existing records for this scan to avoid duplication
        existing_host_ids = [h.id for h in Host.query.filter_by(scan_id=scan_id).all()]
        if existing_host_ids:
            Port.query.filter(Port.host_id.in_(existing_host_ids)).delete(synchronize_session=False)
        Host.query.filter_by(scan_id=scan_id).delete(synchronize_session=False)
        NSEResult.query.filter_by(scan_id=scan_id).delete(synchronize_session=False)

        created_hosts_count = 0
        total_open_ports = 0

        for host_data in parsed_data.get('hosts', []):
            host = Host(
                scan_id=scan.id,
                ip_address=host_data['ip_address'],
                hostname=host_data.get('hostname'),
                state=host_data.get('state', 'up'),
                os_information=host_data.get('os_information')
            )
            active_session.add(host)
            active_session.flush()  # Generate host.id for relationships
            created_hosts_count += 1

            # Add Ports
            for port_data in host_data.get('ports', []):
                port = Port(
                    host_id=host.id,
                    port_number=port_data['port_number'],
                    protocol=port_data.get('protocol', 'tcp'),
                    state=port_data.get('state', 'open'),
                    service=port_data.get('service'),
                    product=port_data.get('product'),
                    version=port_data.get('version'),
                    extra_info=port_data.get('extra_info')
                )
                active_session.add(port)
                if port.state.lower() == 'open':
                    total_open_ports += 1

            # Add NSE Results
            for script_data in host_data.get('scripts', []):
                nse = NSEResult(
                    scan_id=scan.id,
                    host_id=host.id,
                    script_id=script_data['script_id'],
                    service=script_data.get('service'),
                    output=script_data.get('output', ''),
                    severity='info'
                )
                active_session.add(nse)

        # Update Scan metadata
        scan.number_of_hosts = created_hosts_count
        scan.number_of_open_ports = total_open_ports
        scan.status = 'completed'
        scan.error_message = None

        active_session.commit()
        logger.info(f"Scan #{scan_id} successfully parsed: {created_hosts_count} hosts, {total_open_ports} open ports.")
        return scan

    except Exception as e:
        active_session.rollback()
        logger.error(f"Database error while storing scan #{scan_id} results: {str(e)}")
        raise XMLParserError(f"Failed to persist parsed scan results: {str(e)}")

def parse_and_store_scan(scan_id: int, xml_path: Optional[str] = None, app=None) -> Scan:
    """
    Complete pipeline: verifies scan, validates XML file, executes parser, and persists to DB.
    """
    from flask import current_app
    app_instance = app or current_app

    with app_instance.app_context():
        scan = db.session.get(Scan, scan_id)
        if not scan:
            raise XMLParserError(f"Scan #{scan_id} not found.")

        target_xml = xml_path or scan.xml_path
        if not target_xml:
            expected_xml = os.path.join(app_instance.config['SCANS_FOLDER'], str(scan_id), 'result.xml')
            target_xml = expected_xml

        try:
            # 1. Validate file safety
            validated_path = validate_xml_file(target_xml, allowed_base_dir=app_instance.config['SCANS_FOLDER'])
            
            # 2. Parse XML
            parsed_data = parse_nmap_xml(validated_path)
            
            # 3. Persist to SQLite
            updated_scan = store_parsed_scan_results(scan_id, parsed_data)
            return updated_scan

        except Exception as e:
            logger.error(f"Error processing XML for scan #{scan_id}: {str(e)}")
            scan.status = 'failed'
            scan.error_message = f"XML Parsing failed: {str(e)}"
            db.session.commit()
            raise
