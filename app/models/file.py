"""
SQLAlchemy model for HTTP request/response pairs and findings
"""
from datetime import datetime
from app import db


class HTTPModel(db.Model):
    """
    HTTP Request / Response model
    """
    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    host = db.Column(db.String(), unique=False, nullable=False)

    application_id = db.Column(db.String(), unique=False, nullable=False)
    added = db.Column(db.DateTime(), nullable=False,
                      default=datetime.utcnow)

    raw_request = db.Column(db.LargeBinary(), unique=False, nullable=False)
    raw_response = db.Column(db.LargeBinary(), unique=False, nullable=False)

    def __repr__(self):
        """
        Get object representation
        :return:
        """
        return f"<{self.host}-{self.id}>"

    def to_obj(self):
        """
        Return the request response model object
        :return:
        """
        return {
            "id": self.id,
            "request": self.raw_request.decode("utf-8", errors="replace"),
            "response": self.raw_response.decode("utf-8", errors="replace"),
            "added": self.added,
            "application_id": self.application_id,
            "host": self.host,
            "findings": []
        }


class HTTPFinding(db.Model):
    """
    HTTP finding model used for request / response vulnerabilities
    """
    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    name = db.Column(db.String(), unique=False, nullable=False)
    remote_id = db.Column(db.Integer(), unique=False, nullable=False)

    severity = db.Column(db.String(), unique=False, nullable=False)
    text = db.Column(db.Text(), unique=False, nullable=True)
    highlight = db.Column(db.String(), unique=False, nullable=True)

    def __init__(self, name, remote_id, severity, text=None, highlight=None):
        """
        Create the finding
        Allows the use of Class**
        :param name:
        :param remote_id:
        :param severity:
        :param text:
        :param highlight:
        """
        self.name = name
        self.remote_id = remote_id
        self.severity = severity
        self.text = text
        self.highlight = highlight

    def __repr__(self):
        """
        Get object representation
        :return:
        """
        return f"<{self.severity}-{self.name}-{self.id}>"

    def to_obj(self):
        """
        Get readable object as dictionary
        :return:
        """
        return {
            "name": self.name,
            "severity": self.severity,
            "remote_id": self.remote_id,
            "text": self.text,
            "highlight": self.highlight
        }
