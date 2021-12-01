"""
HTTP finding classes and stuff
"""
import json
import logging
import re

from urllib.parse import unquote
from enum import Enum

from ext.httpsec.jwtutils import get_jwt


class FindingSeverity(str, Enum):
    """
    Explains itself right?
    """
    INFO = 'INFO'
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'


class Finding:
    """
    Wrapper for a "Finding"
    """
    name: str = None
    text: str = None
    severity: FindingSeverity = FindingSeverity.INFO
    remote_id: int = None
    highlight: str = None

    def __init__(self, name, text=None,
                 severity=FindingSeverity.INFO,
                 remote_id=None, highlight=None):
        """
        Build the finding
        :param name:
        :param text:
        :param severity:
        :param remote_id:
        :param highlight:
        """
        self.name = name
        self.text = text
        self.severity = severity
        self.remote_id = remote_id
        self.highlight = highlight

    def to_object(self):
        """
        Return as dictionary
        :return:
        """
        return {
            "name": self.name,
            "text": self.text,
            "severity": self.severity.name,
            "remote_id": self.remote_id,
            "highlight": self.highlight
        }

    def __repr__(self):
        """
        Return representation of the object
        :return:
        """
        return f"{self.name}-{self.remote_id}"


class SecurityScanner:
    """
    Class to scan request / response pairs for common issues
    """
    request = b""
    response = b""

    remote_id = None
    findings = []

    def __init__(self, request, response, remote_id):
        """
        Build the class
        :param request:
        :param response:
        :param remote_id:
        """
        self.request = request
        self.response = response
        self.remote_id = remote_id

    def run(self):
        """
        Check response headers and return stuff
        :return:
        """
        resp_chk = ResponseHeaderChecker(self.response)
        resp_chk.check_cookies()
        resp_chk.check_headers()
        self.findings.extend(resp_chk.findings)
        for finding in self.findings:
            finding.remote_id = self.remote_id


class ResponseHeaderChecker:
    """
    Class for dectecting common issues in response headers
    """
    response_headers = []
    findings = []

    def __init__(self, raw_response: bytes):
        """
        Build header pair out of response
        :param raw_response:
        """
        # cut the first one
        parts = raw_response.split(b"\n")[1:]
        for entry in parts:
            entry = entry.strip()
            if entry == b"":
                # we have reached the end of the headers
                break
            header_kvp = entry.split(b": ")
            if len(header_kvp) < 2:
                logging.warning("Malformed header syntax: %s", entry)
                continue
            self.response_headers.append(
                (header_kvp[0], b": ".join(header_kvp[1:]))
            )

    def check_headers(self):
        """
        Check for version disclosure
        :return:
        """
        for header_group in self.response_headers:
            h_key, h_value = header_group
            h_decoded = h_value.decode()
            if h_key.lower() == b"x-powered-by" and re.search(r'\d+\.', h_decoded):
                self.findings.append(
                    Finding(
                        name="Web server backend version exposure",
                        text=h_decoded,
                        severity=FindingSeverity.LOW
                    )
                )
            if h_key.lower() == b"server" and re.search(r'\d+\.', h_decoded):
                self.findings.append(
                    Finding(
                        name="Web server server version exposure",
                        text=h_decoded,
                        severity=FindingSeverity.LOW
                    )
                )

    def check_cookies(self):
        """
        Check Set-Cookie headers
        :return:
        """
        for header_group in self.response_headers:
            h_key, h_value = header_group
            if h_key.lower() != b"set-cookie":
                continue
            try:
                self.check_cookie(h_value)
            except Exception as invalid_cookie:
                logging.warning("Malformed cookie data: %s - %s", h_value, str(invalid_cookie))

    def check_cookie(self, cookie_data):
        """
        Checks cookies for
        - Security flags
        - JWT's
        :param cookie_data:
        :return:
        """
        cookie_data = cookie_data.decode()
        cookie_split = cookie_data.split(";")
        security_options = [x.strip().lower() for x in cookie_split[1:]]
        if "secure" not in security_options:
            self.findings.append(
                Finding(
                    name="Cookie without 'Secure' flag set",
                    text=cookie_data,
                    severity=FindingSeverity.LOW
                )
            )
        if "httponly" not in security_options:
            self.findings.append(
                Finding(
                    name="Cookie without 'HttpOnly' flag set",
                    text=cookie_data,
                    severity=FindingSeverity.LOW
                )
            )
        has_path = False
        has_same_site = False
        for sec_opt in security_options:
            if sec_opt.startswith("path="):
                has_path = True
            if sec_opt.startswith("samesite"):
                has_same_site = True
        if not has_path:
            self.findings.append(
                Finding(
                    name="Cookie without 'Path' prefix set",
                    text=cookie_data,
                    severity=FindingSeverity.LOW
                )
            )
        if not has_same_site:
            self.findings.append(
                Finding(
                    name="Cookie without 'SameSite' flag set",
                    text=cookie_data,
                    severity=FindingSeverity.LOW
                )
            )
        h_values = cookie_split[0].split("=")
        if len(h_values) == 1:
            return
        cookie_key = unquote(h_values[0])
        cookie_value = unquote("=".join(h_values[1:]))
        if cookie_value.startswith("ey"):
            get_jwt_data = get_jwt(cookie_value)
            if get_jwt_data:
                self.findings.append(
                    Finding(
                        name=f"JWT found in cookie {cookie_key}",
                        text=json.dumps(get_jwt_data),
                        severity=FindingSeverity.INFO,
                        highlight=h_values[1]
                    )
                )
                if get_jwt_data.get("guessable_key", None):
                    self.findings.append(
                        Finding(
                            name=f"JWT found with default key: {get_jwt_data.get('guessable_key')}",
                            text=json.dumps(get_jwt_data),
                            severity=FindingSeverity.HIGH,
                            highlight=h_values[1]
                        )
                    )
