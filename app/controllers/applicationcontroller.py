"""
Flask routes for static analysis features
"""
import os
import logging

from tempfile import NamedTemporaryFile
from hashlib import sha1
from flask import (render_template, request, redirect, url_for, jsonify)
from app import flask, db


from app.models.application import (
    MobileApplication, MobileApplicationFlow,
    MobileFile, MobileFileFinding)
from app.models.security import MobileBinaryResult

from ext.processor import initialize
from ext.apkutils import process

logging.getLogger("pyaxmlparser").setLevel(logging.INFO)


@flask.route("/", methods=["GET"])
def home_route():
    """
    Show the home route with the apk upload form
    :return:
    """
    return render_template("index.html")


@flask.route("/api/status/<app_id>", methods=["GET"])
def get_app_sub_status(app_id):
    """
    Get the status of the current running scan
    :param app_id:
    :return:
    """
    parse_log = MobileApplicationFlow.query.filter(
        MobileApplicationFlow.application_id == app_id
    ).order_by(MobileApplicationFlow.id.desc())
    out_res = []
    for log_entry in parse_log.all():
        out_res.append({
            "name": log_entry.key,
            "data": log_entry.data,
            "added": log_entry.added}
        )
    return jsonify(out_res)


@flask.route("/scans", methods=["GET"])
def scanned_apks():
    """
    Return a list of scanned applications
    :return:
    """
    list_apks = MobileApplication.query.all()
    return render_template("scans.html", scans=list_apks)


@flask.route("/scan/<app_id>/remove", methods=["GET"])
def remove_scanned_apk(app_id):
    """
    Return a list of scanned applications
    :return:
    """
    sub_stmt = db.session.query(
        MobileFile.id
    ).filter(MobileFile.application_id == app_id)
    db.session.query(
        MobileFileFinding
    ).filter(MobileFileFinding.file_id.in_(sub_stmt)).delete(synchronize_session=False)
    db.session.query(MobileFile).filter(
        MobileFile.application_id == app_id).delete(synchronize_session=False)
    db.session.query(MobileApplicationFlow).filter(
        MobileApplicationFlow.application_id == app_id
    ).delete(synchronize_session=False)
    db.session.query(MobileApplication).filter(
        MobileApplication.checksum == app_id
    ).delete(synchronize_session=False)
    db.session.query(MobileBinaryResult).filter(
        MobileBinaryResult.application_id == app_id
    ).delete(synchronize_session=False)
    db.session.commit()
    return redirect(url_for('scanned_apks'))


@flask.route("/process", methods=["POST"])
def process_apk():
    """
    Start a new apk analysis run (Thread)
    :return:
    """
    get_apk = request.files.get("apk", default=None)
    if not get_apk:
        return render_template("index.html", message="No APK selected")
    if get_apk.filename.endswith(".apks"):
        return render_template(
            "index.html",
            message="Split APK files are currently not supported"
        )
    if get_apk.mimetype != "application/vnd.android.package-archive":
        return render_template(
            "index.html",
            message=f"Unknown filetype: {get_apk.mimetype}"
        )
    with NamedTemporaryFile(suffix=".apk", mode="wb", delete=False) as tmp_zipfile:
        apk_bytes = get_apk.stream.read()
        tmp_zipfile.write(apk_bytes)
        apk_sum_create = sha1(apk_bytes).hexdigest()
        print(f"Saved to {tmp_zipfile.name}")
        print(f"APK checksum: {apk_sum_create}")
        tmp_zipfile.close()
        check = MobileApplication.query.filter_by(checksum=apk_sum_create)
        if check.count():
            return render_template("index.html", message="APK was already analysed")
        output = process(tmp_zipfile.name)
        if not output:
            return render_template("index.html", message="Error processing APK")
        new_mobapp = MobileApplication()
        new_mobapp.name = output['common']['package']
        new_mobapp.checksum = apk_sum_create
        db.session.add(new_mobapp)
        db.session.commit()
        server_url = "http://localhost:7300/"
        print(f"Reporting to {server_url}")
        initialize(
            endpoint=server_url,
            apk_checksum=apk_sum_create,
            apk_location=tmp_zipfile.name
        )
    return redirect(url_for("get_apk_dashboard", app_id=new_mobapp.checksum))


@flask.route("/process/<apk_name>", methods=["GET"])
def process_apk_from_local(apk_name):
    """
    Start a new apk analysis run (Thread)
    :return:
    """
    get_location = os.path.join(
        os.path.dirname(__file__),
        f"..{os.path.sep}",
        f"..{os.path.sep}",
        "ext",
        "sources",
        apk_name
    )
    get_location = os.path.abspath(get_location)
    if not apk_name.endswith(".apk"):
        return render_template("index.html", message="Invalid apk file")
    with open(get_location, "rb") as tmp_zipfile:
        apk_bytes = tmp_zipfile.read()
        apk_sum_create = sha1(apk_bytes).hexdigest()
        print(f"Saved to {apk_name}")
        print(f"APK checksum: {apk_sum_create}")
        check = MobileApplication.query.filter_by(checksum=apk_sum_create)
        if check.count():
            return render_template("index.html", message="APK was already analysed")
        output = process(get_location)
        if not output:
            return render_template("index.html", message="Error processing APK")
        new_mobapp = MobileApplication()
        new_mobapp.name = output['common']['package']
        new_mobapp.checksum = apk_sum_create
        db.session.add(new_mobapp)
        db.session.commit()
        server_url = "http://localhost:7300/"
        print(f"Reporting to {server_url}")
        initialize(
            endpoint=server_url,
            apk_checksum=apk_sum_create,
            apk_location=get_location
        )
    return redirect(url_for("get_apk_dashboard", app_id=new_mobapp.checksum))


@flask.route("/api/process", methods=["POST"])
def process_apk_api():
    """
    Start a new apk analysis run (Thread)
    :return:
    """
    get_apk = request.files.get("apk", default=None)
    if not get_apk:
        return jsonify({
            "status": False,
            "error": "No file supplied"
        })
    if get_apk.filename.endswith(".apks"):
        return jsonify({
            "status": False,
            "error": "Unsupported format"
        })
    if get_apk.mimetype != "application/vnd.android.package-archive":
        return jsonify({
            "status": False,
            "error": "Unknown filetype"
        })
    with NamedTemporaryFile(suffix=".apk", mode="wb", delete=False) as temp_zipfile:
        apk_bytes = get_apk.stream.read()
        temp_zipfile.write(apk_bytes)
        apk_sum_create = sha1(apk_bytes).hexdigest()
        print(f"Saved to {temp_zipfile}")
        print(f"APK checksum: {apk_sum_create}")
        temp_zipfile.close()
        check = MobileApplication.query.filter_by(checksum=apk_sum_create)
        if check.count():
            return jsonify({
                "status": False,
                "error": "Already analysed"
            })
        output = process(temp_zipfile.name)
        if not output:
            return jsonify({
                "status": False,
                "error": "Error processing apk"
            })
        new_mobapp = MobileApplication()
        new_mobapp.name = output['common']['package']
        new_mobapp.checksum = apk_sum_create
        db.session.add(new_mobapp)
        db.session.commit()
        server_url = "http://localhost:7300/"
        print(f"Reporting to {server_url}")
        initialize(endpoint=server_url, apk_checksum=apk_sum_create, apk_location=temp_zipfile.name)
    return jsonify({
        "status": True,
        "checksum": new_mobapp.checksum
    })
