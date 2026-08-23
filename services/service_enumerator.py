"""
Service Enumeration Engine
===========================
Identifies, normalizes, and groups open ports and services discovered during Nmap scans.
"""

from typing import List, Dict, Any, Optional
from models import db, Port, Host, Scan

def get_service_category(service_name: Optional[str], port_number: int) -> str:
    """
    Normalizes service names reported by Nmap into standard service categories.
    Does NOT infer purely from port unless service_name is absent.
    """
    name = (service_name or '').lower().strip()
    
    if name:
        if 'https' in name or name == 'ssl/http' or name == 'http-ssl':
            return 'HTTPS'
        if 'http' in name:
            return 'HTTP'
        if 'ssh' in name:
            return 'SSH'
        if 'dns' in name or name == 'domain':
            return 'DNS'
        if 'ftp' in name:
            return 'FTP'
        if 'smtp' in name:
            return 'SMTP'
        if 'mysql' in name:
            return 'MySQL'
        if 'postgres' in name or 'postgresql' in name:
            return 'PostgreSQL'
        if 'rdp' in name or name == 'ms-wbt-server':
            return 'RDP'
        if 'smb' in name or name == 'microsoft-ds' or name == 'netbios-ssn':
            return 'SMB'
        return 'Other'

    # Fallback to port only if service name is completely unavailable
    if port_number == 80:
        return 'HTTP'
    if port_number == 443:
        return 'HTTPS'
    if port_number == 22:
        return 'SSH'
    if port_number == 53:
        return 'DNS'
    if port_number == 21:
        return 'FTP'
    if port_number == 25:
        return 'SMTP'
    if port_number == 3306:
        return 'MySQL'
    if port_number == 5432:
        return 'PostgreSQL'
    if port_number == 3389:
        return 'RDP'
    if port_number in (139, 445):
        return 'SMB'
        
    return 'Other'

def enumerate_services(
    user_id: int, 
    filters: Optional[Dict[str, Any]] = None, 
    search_query: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Retrieves and filters active services from all scans owned by the user.
    """
    query = db.session.query(Port, Host, Scan).join(Host, Port.host_id == Host.id).join(Scan, Host.scan_id == Scan.id)
    
    # Enforce scan ownership check
    query = query.filter(Scan.user_id == user_id)
    
    # Only show open or active ports (or as filtered)
    if filters and 'state' in filters and filters['state']:
        query = query.filter(Port.state.ilike(filters['state']))
    else:
        query = query.filter(Port.state.ilike('open'))

    if filters:
        if 'service' in filters and filters['service']:
            query = query.filter(Port.service.ilike(f"%{filters['service']}%"))
        if 'protocol' in filters and filters['protocol']:
            query = query.filter(Port.protocol.ilike(filters['protocol']))
        if 'host' in filters and filters['host']:
            query = query.filter(Host.ip_address.ilike(f"%{filters['host']}%"))

    # Apply global search query across host, IP, port, service, product, version
    if search_query:
        s_like = f"%{search_query}%"
        query = query.filter(
            (Host.ip_address.ilike(s_like)) |
            (Host.hostname.ilike(s_like)) |
            (db.cast(Port.port_number, db.String).ilike(s_like)) |
            (Port.service.ilike(s_like)) |
            (Port.product.ilike(s_like)) |
            (Port.version.ilike(s_like))
        )

    results = query.all()
    enumerated = []
    
    for port, host, scan in results:
        category = get_service_category(port.service, port.port_number)
        
        enumerated.append({
            'port_id': port.id,
            'host_id': host.id,
            'scan_id': scan.id,
            'host_ip': host.ip_address,
            'hostname': host.hostname or '—',
            'port': port.port_number,
            'protocol': port.protocol,
            'state': port.state,
            'service': port.service or 'unknown',
            'product': port.product or '—',
            'version': port.version or 'Not detected',
            'extra_info': port.extra_info or '—',
            'category': category
        })
        
    return enumerated

def get_service_counts(user_id: int) -> Dict[str, int]:
    """
    Aggregates service counts by category for all scans owned by the user.
    """
    services = enumerate_services(user_id)
    counts = {
        'HTTP': 0,
        'HTTPS': 0,
        'SSH': 0,
        'DNS': 0,
        'FTP': 0,
        'SMTP': 0,
        'MySQL': 0,
        'PostgreSQL': 0,
        'RDP': 0,
        'SMB': 0,
        'Other': 0
    }
    for s in services:
        cat = s['category']
        if cat in counts:
            counts[cat] += 1
        else:
            counts['Other'] += 1
    return counts
