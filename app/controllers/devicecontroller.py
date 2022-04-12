"""
Control various misc features of the device
"""
import json
import zipfile
import base64

from ext.adb import ADBStrategy

from flask import request, jsonify, render_template
from app import flask, db


@flask.route("/dynamic/<device_id>/logcat/get", methods=["GET"])
def logcat_get_data(device_id):
    """
    Get the logcat stream of the device
    Optional parameters: clean and search
    :param device_id:
    :return:
    """
    get_stream = ADBStrategy()
    get_stream.device = device_id
    output_data = []
    if request.args.get("clean", None):
        get_stream.run(["logcat", "-c"])
    log_data = get_stream.run(["logcat", "-d"], no_output=True).stdout.decode()
    output_data = [x.strip() for x in log_data.split("\n")]
    # hide the spam headers
    output_data = [x for x in output_data if not x.startswith("---------")]
    keyword = request.args.get("search", None)
    if keyword:
        output_data = [x for x in output_data if keyword.lower() in x.lower()]
    return render_template("dynamic/logcat.html", log_data=output_data, device_id=device_id)


@flask.route("/device/<device_id>/api/logcat/stream", methods=["GET"])
def logcat_get_data_stream(device_id):
    """
    Get the logcat stream of the device
    Optional parameters: clean and search
    :param device_id:
    :return:
    """
    get_stream = ADBStrategy()
    get_stream.device = device_id
    log_data = get_stream.run(["logcat", "-d"], no_output=True).stdout.decode()
    output_data = [x.strip() for x in log_data.split("\n")]
    output_data = [x for x in output_data if not x.startswith("---------")]
    keyword = request.args.get("search", None)
    if keyword:
        output_data = [x for x in output_data if keyword in x]
    get_stream.run(["logcat", "-c"])
    return jsonify(output_data)

