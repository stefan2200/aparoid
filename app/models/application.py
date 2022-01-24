"""
Models for application specific stuff
For more information on what these models do \
please check the controller that sounds like it has \
something to do with the model name
"""

from datetime import datetime
from app import db


class MobileApplication(db.Model):
    """
    Mobile Application Model
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=False, nullable=False)
    version_name = db.Column(db.String(120), unique=False, nullable=True)
    version_code = db.Column(db.String(120), unique=False, nullable=True)
    checksum = db.Column(db.String(40), unique=False, nullable=True)
    state = db.Column(db.Integer, unique=False, nullable=False, default=1)
    icon = db.Column(db.Text(), unique=False, nullable=True)

    def __repr__(self):
        """
        Return representation of the object
        :return:
        """
        return f"<{self.name}>"

    def to_readable(self):
        """
        Return readable dict object
        :return:
        """
        return {
            "id": self.id,
            "name": self.name,
            "checksum": self.checksum,
            "version_name": self.version_name,
            "version_code": self.version_code
        }

    def get_apk(self, check_only=False):
        """
        Get the APK file for a stored mobile application
        :param check_only:
        :return:
        """
        check_mobile_file = MobileFile.query.filter(
            MobileFile.application_id == self.checksum
        ).filter(
            MobileFile.name == f"{self.name}.apk"
        )
        if check_only:
            return check_mobile_file.count() > 0
        if check_mobile_file.count():
            return check_mobile_file.first()
        return None


class MobileFile(db.Model):
    """
    Mobile File Model
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(245), unique=False, nullable=False)
    application_id = db.Column(db.String(40), unique=False, nullable=False)
    mime = db.Column(db.String(50), unique=False, nullable=False)
    data = db.Column(db.LargeBinary(), unique=False, nullable=False)

    def __repr__(self):
        """
        Return representation of the object
        :return:
        """
        return f"<{self.name}>"

    def readable(self):
        """
        Get readable instance of the File
        :return:
        """
        return dict(
            filename=self.name,
            mime=self.mime,
            data=self.data
        )


class MobileFileFinding(db.Model):
    """
    Mobile File Finding Model
    """
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(245), unique=False, nullable=False)
    application_id = db.Column(db.String(40), unique=False, nullable=False)
    file_id = db.Column(db.Integer(), unique=False, nullable=False)
    text = db.Column(db.Text(), unique=False, nullable=True)
    description = db.Column(db.Text(), unique=False, nullable=True)
    filename = db.Column(db.Text(), unique=False, nullable=True)
    file_line = db.Column(db.Integer(), unique=False, nullable=True)
    highlight = db.Column(db.String(245), unique=False, nullable=True)
    mobile_asvs = db.Column(db.String(20), unique=False, nullable=True)
    severity = db.Column(db.String(10), unique=False, nullable=True)

    def readable(self):
        """
        Get readable fields from the object
        :return:
        """
        return dict(
            name=self.name,
            filename=self.filename,
            line=self.file_line,
            description=self.description,
            severity=self.severity,
            text=self.text
        )

    def __repr__(self):
        return f"<self.filename-{self.name}>"


class MobileApplicationFlow(db.Model):
    """
    Mobile Application Flow Model
    """
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(245), unique=False, nullable=False)
    application_id = db.Column(db.String(40), unique=False, nullable=False)
    added = db.Column(db.DateTime, nullable=False,
                      default=datetime.utcnow)
    data = db.Column(db.Text(), unique=False, nullable=False)

    def __repr__(self):
        """
        Return representation of the object
        :return:
        """
        return f"<{self.key}>"

    def readable(self):
        """
        Get readable instance of the File
        :return:
        """
        return dict(
            key=self.key,
            data=self.data
        )


class DynamicApplicationLog(db.Model):
    """
    Dynamic application log Model
    """
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(245), unique=False, nullable=False)
    application_id = db.Column(db.String(40), unique=False, nullable=True)
    added = db.Column(db.DateTime, nullable=False,
                      default=datetime.utcnow)
    data = db.Column(db.Text(), unique=False, nullable=True)

    def __init__(self, key, application=None, data=None):
        """
        Create the log object
        """
        self.key = key
        self.application_id = application
        self.data = data


    def __repr__(self):
        """
        Return representation of the object
        :return:
        """
        return f"<{self.key}>"

    def readable(self):
        """
        Get readable instance of the File
        :return:
        """
        return dict(
            key=self.key,
            data=self.data,
            added=self.added
        )
