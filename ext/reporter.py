"""
Class to report data to the remote server
"""
import base64
import json
import logging
import time
from urllib.parse import urljoin
import requests


class Reporter:
    """
    Class containing only static methods
    """
    @staticmethod
    def push_log(endpoint, application_id, key, text=None, stdout=True, retry=False):
        """
        Push log information to the remote server
        :param endpoint:
        :param application_id:
        :param key:
        :param text:
        :param stdout:
        :param retry:
        :return:
        """
        url = urljoin(endpoint, f"/api/put/{application_id}")
        if stdout:
            logging.info(f"[{key}-{application_id}]: {text}")
        try:
            requests.post(
                url,
                data={"key": key, "data": text},
                timeout=(3, 120)
            )
        except requests.RequestException:
            if retry:
                return
            time.sleep(1)
            return Reporter.push_log(
                endpoint, application_id, key,
                text=None, stdout=True, retry=True
            )

    @staticmethod
    def push_file(endpoint, application_id, filepath=None, name=None, retry=False):
        """
        Push a file to the remote server
        :param endpoint:
        :param application_id:
        :param filepath:
        :param name:
        :param retry:
        :return:
        """
        url = urljoin(endpoint, f"/api/put_bundle/{application_id}")
        if not name:
            name = filepath
        try:
            requests.post(
                url,
                files={'file': open(filepath, 'rb')},
                timeout=(3, 1200)
            )
        except requests.RequestException:
            if retry:
                return
            time.sleep(1)
            return Reporter.push_file(
                endpoint, application_id,
                filepath=filepath, name=name, retry=True
            )

    @staticmethod
    def push_binary_result(endpoint, application_id, binaries, retry=False):
        """
        Push binary analysis information to the remote server
        :param endpoint:
        :param application_id:
        :param binaries:
        :param retry:
        :return:
        """
        url = urljoin(endpoint, f"/api/put_bin_result/{application_id}")
        try:
            requests.post(
                url,
                data={"binaries": binaries},
                timeout=(3, 240)
            )
        except requests.RequestException:
            if retry:
                return
            time.sleep(1)
            return Reporter.push_binary_result(endpoint, application_id, binaries, retry=True)

    @staticmethod
    def push_http_result(endpoint, application_id, host, request, response, retry=False):
        """
        Push HTTP Request / Response to the remote server
        :param endpoint:
        :param application_id:
        :param host:
        :param request:
        :param response:
        :param retry:
        :return:
        """
        request = base64.b64encode(request).decode()
        response = base64.b64encode(response).decode()

        url = urljoin(endpoint, f"/api/put_http_result/{application_id}")
        try:
            res = requests.post(url, data={"request": request, "response": response, "host": host})
        except requests.RequestException:
            if retry:
                return None
            time.sleep(1)
            return Reporter.push_http_result(endpoint, application_id,
                                             host, request, response, retry=True)

        return res.json()

    @staticmethod
    def push_http_finding(endpoint, application_id, finding_data, retry=False):
        """
        Push HTTP finding to the remote server
        :param endpoint:
        :param application_id:
        :param finding_data:
        :param retry:
        :return:
        """
        finding = json.dumps([finding.to_object() for finding in finding_data])

        url = urljoin(endpoint, f"/api/put_http_finding/{application_id}")
        try:
            requests.post(url, data={"finding": finding})
        except requests.RequestException:
            if retry:
                return
            time.sleep(1)
            return Reporter.push_http_finding(endpoint, application_id,
                                              finding_data, retry=True)
