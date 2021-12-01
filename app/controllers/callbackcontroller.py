"""
Script to handle callbacks from the started analysis thread
"""
import json
import zipfile
import base64

from io import BytesIO

from flask import request, jsonify
from app import flask, db

from app.controllers.asynccontroller import run_on_zip_queue
from app.models.application import (MobileApplication,
                                    MobileApplicationFlow, MobileFile)
from app.models.security import MobileBinaryResult
from app.models.file import HTTPModel, HTTPFinding


@flask.route("/api/pull/<app_id>", methods=["GET"])
def api_pull_logs(app_id):
    """
    Get the current logs for the selected application
    :param app_id:
    :return:
    """
    get_apk_data = MobileApplication.query.filter(MobileApplicationFlow.application_id == app_id)
    if not get_apk_data.count():
        return jsonify([])
    return jsonify(get_apk_data.all())


@flask.route("/api/put_http_result/<app_id>", methods=["POST"])
def api_put_request_response(app_id):
    """
    Set a Request, Response an Host from the Kafka collector agent
    :param app_id:
    :return:
    """
    request_data = request.form.get("request", None)
    response_data = request.form.get("response", None)
    host = request.form.get("host", None)
    http_req_resp = HTTPModel()
    http_req_resp.raw_request = base64.b64decode(request_data)
    http_req_resp.raw_response = base64.b64decode(response_data)
    http_req_resp.application_id = app_id
    http_req_resp.host = host
    db.session.add(http_req_resp)
    db.session.commit()
    return jsonify({"status": True, "remote_id": http_req_resp.id})


@flask.route("/api/put_http_finding/<app_id>", methods=["POST"])
def api_put_http_finding(app_id):
    """
    Create a finding based on a defined JSON structure
    - Works remarkably well :)
    :param app_id:
    :return:
    """
    finding_data = request.form.get("finding", None)
    finding_data = json.loads(finding_data)
    for finding in finding_data:
        http_req_resp = HTTPFinding(**finding)
        db.session.add(http_req_resp)
    db.session.commit()
    return jsonify({"status": True})


@flask.route("/api/put/<app_id>", methods=["POST"])
def api_push_log(app_id):
    """
    Push a log entry from the processing thread
    :param app_id:
    :return:
    """
    log_key = request.form.get("key", None)
    log_data = request.form.get("data", None)
    push_log = MobileApplicationFlow()
    push_log.key = log_key
    push_log.data = log_data
    push_log.application_id = app_id
    db.session.add(push_log)
    db.session.commit()
    return jsonify({"status": True})


@flask.route("/api/put_bin_result/<app_id>", methods=["POST"])
def api_push_bin_result(app_id):
    """
    Upload a binary file to the database
    :param app_id:
    :return:
    """
    binary_data = request.form.get("binaries")
    bin_dec = json.loads(binary_data)
    for binary in bin_dec:
        binary_location = binary
        binary_data = bin_dec[binary]
        push_binary = MobileBinaryResult()
        push_binary.binary = binary_location
        push_binary.data = json.dumps(binary_data)
        push_binary.application_id = app_id
        db.session.add(push_binary)
    db.session.commit()
    return jsonify({"status": True})


@flask.route("/api/put_file/<app_id>", methods=["POST"])
def api_push_file(app_id):
    """
    Upload a single file (including location and mime-type)
    :param app_id:
    :return:
    """
    file_data = request.files.get("file", None)
    file_name = request.args.get("name", None)
    file_mime = request.args.get("mime", None)
    push_file = MobileFile()
    push_file.name = file_name
    push_file.data = file_data.stream.read()
    push_file.mime = file_mime
    push_file.application_id = app_id
    db.session.add(push_file)
    db.session.commit()
    return jsonify({"status": True})


@flask.route("/api/put_bundle/<app_id>", methods=["POST"])
def api_push_file_bundle(app_id):
    """
    Upload a large zip bundle of files to the application
    :param app_id:
    :return:
    """
    file_data = request.files.get("file", None)
    buffer = BytesIO(file_data.stream.read())
    with zipfile.ZipFile(buffer) as read_zipfile:
        run_on_zip_queue(zip_data=read_zipfile, app_id=app_id)

    return jsonify({"status": True})
