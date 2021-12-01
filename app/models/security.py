"""
Models for security specific stuff
For more information on what these models do \
please check the controller that sounds like it has \
something to do with the model name
"""

from datetime import datetime
from app import db


class MobileSecurityFinding(db.Model):
    """
    Mobile Security Finding Model
    """
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(245), unique=False, nullable=False)
    application_id = db.Column(db.String(40), unique=False, nullable=False)
    added = db.Column(db.DateTime, nullable=False,
                      default=datetime.utcnow)
    data = db.Column(db.Text(), unique=False, nullable=False)
    cvss = db.Column(db.String(35), unique=False, nullable=True, default=None)
    masvs = db.Column(db.String(20), unique=False, nullable=True, default=None)
    file_id = db.Column(db.Integer, unique=False, nullable=True)


class MobileBinaryResult(db.Model):
    """
    Mobile Binary Result Model
    """
    id = db.Column(db.Integer, primary_key=True)
    binary = db.Column(db.String(245), unique=False, nullable=False)
    application_id = db.Column(db.String(40), unique=False, nullable=False)
    added = db.Column(db.DateTime, nullable=False,
                      default=datetime.utcnow)
    data = db.Column(db.Text(), unique=False, nullable=False)
