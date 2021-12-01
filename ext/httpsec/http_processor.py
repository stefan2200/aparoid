"""
Class for processing Kafka request / response entries
Runs async
"""
import re
import subprocess
import sys
import os
import json
import logging
import base64
import psutil
import kafka
from kafka import TopicPartition

root_app = os.path.join(
    os.path.dirname(__file__),
    f"..{os.path.sep}",
    f"..{os.path.sep}"
)
sys.path.insert(0, root_app)

from ext.httpsec.secscan import SecurityScanner
from ext.reporter import Reporter

from config import Config


class Processor:
    """
    Parser request and responses
    """
    def __init__(self):
        self.endpoint = None
        self.application_id = None
        self.ignored_types = [x.encode() for x in [
            ".css", ".scss", ".gif",
            ".png", ".svg", ".bmp",
            ".jpg", ".webm", ".mp4",
            ".jpeg", ".tiff", ".woff2",
            ".ttf", ".eot", ".ico"
        ]]

        self.host_filter = []
        self.blocked_host_filter = [
            "google.com"
        ]

        self.connection = kafka.KafkaConsumer(
            bootstrap_servers=Config.kafka_servers,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            auto_offset_reset='earliest',
            group_id=None
        )

    def _is_ignored_type(self, path_file):
        """
        Check the collected filetype and check if it is in the ignored list
        :param path_file:
        :return:
        """
        path_file = path_file.split(b"?")[0].split(b"#")[0]
        for ign in self.ignored_types:
            if path_file.endswith(ign):
                print(f"Skipping ignored ext {ign}")
                return True
        return False

    def _is_allowed_host(self, host):
        """
        Allows a host filter to be used
        By default it hides all connections to *.google.com
        :param host:
        :return:
        """
        for bad_host in self.blocked_host_filter:
            if host.endswith(bad_host):
                print(f"Skipping ignored host {bad_host}")
                return False
        if not self.host_filter:
            return True
        for allowed in self.host_filter:
            if host.endswith(allowed):
                return True
        print(f"Skipping ignored host {host}")
        return False

    def process_and_send_data(self, enc_request_response):
        """
        Runs on every Kafka message
        - parses the request and response
        - does some basic processing
        - save to app
        :param enc_request_response:
        :return:
        """
        request = base64.b64decode(enc_request_response.get("request", ""))
        request_lines = request.split(b"\r\n")
        if not request:
            print("Invalid request")
            return
        request_path = request_lines[0].split(b" ")[1]
        if self._is_ignored_type(request_path):
            return

        host_line = None
        for line in request_lines:
            if line.startswith(b"Host: "):
                host_line = line.split(b"Host: ")[1].decode()

        if not host_line:
            host_line_from_url = re.search(r"https?://(.+?)/", request_path.decode())
            if host_line_from_url:
                host_line = host_line_from_url.group(1)
            else:
                print("Invalid host line")
                return

        if not self._is_allowed_host(host_line):
            return
        logging.info("Processed entry for host: %s", host_line)

        response = base64.b64decode(enc_request_response.get("response", ""))
        # upload
        result = Reporter.push_http_result(
            endpoint=self.endpoint,
            application_id=self.application_id,
            request=request,
            response=response,
            host=host_line
        )
        if result and result.get("status", None):
            scanner = SecurityScanner(
                request=request,
                response=response,
                remote_id=result.get("remote_id")
            )
            scanner.run()
            if scanner.findings:
                Reporter.push_http_finding(
                    endpoint=self.endpoint,
                    application_id=self.application_id,
                    finding_data=scanner.findings
                )

    def get_next_entry(self):
        """
        Start async processing of Kafka messages
        :return:
        """
        print("Starting collector agent")
        partition = TopicPartition(f"http-{self.application_id}", 0)
        self.connection.assign([partition])
        self.connection.poll()
        self.connection.seek_to_end()
        print("Collector agent successfully subscribed to topic")
        for entry in self.connection:
            enc_request_response = entry.value
            print("Processing new entry")
            self.process_and_send_data(enc_request_response)


def async_start(app_id):
    """
    Start an asynchronous instance of the collector
    Window detaches on Windows
    :param app_id:
    :return:
    """
    if os.name == 'nt':
        pid = subprocess.Popen([sys.executable, __file__, app_id], creationflags=0x00000008)
    else:
        pid = subprocess.Popen([sys.executable, __file__, app_id])
    return pid.pid


def async_kill(app_id):
    """
    Kill the current running collector agent
    :param app_id:
    :return:
    """
    for process in psutil.process_iter():
        try:
            cmdline = process.cmdline()
            if str(__file__) in cmdline and app_id in cmdline:
                process.kill()
                return True
        except psutil.AccessDenied:
            pass
    return False


def async_is_running(app_id):
    """

    :param app_id:
    :return:
    """
    for process in psutil.process_iter():
        try:
            cmdline = process.cmdline()
            if str(__file__) in cmdline and app_id in cmdline:
                return process.pid
        except psutil.AccessDenied:
            pass
    return False


if __name__ == '__main__':
    try:
        application_id = sys.argv[1]
        p = Processor()
        p.endpoint = "http://127.0.0.1:7300/"
        p.application_id = application_id
        p.get_next_entry()
    except Exception as e:
        logging.error("I crashed:")
        logging.error(str(e))
        x = input("Press any key to exit.")
