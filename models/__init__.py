from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

from models.user import User
from models.scan import Scan
from models.host import Host
from models.port import Port
from models.nse_result import NSEResult
from models.finding import Finding
from models.report import Report
from models.authorized_target import AuthorizedTarget

__all__ = ['db', 'User', 'Scan', 'Host', 'Port', 'NSEResult', 'Finding', 'Report', 'AuthorizedTarget']
