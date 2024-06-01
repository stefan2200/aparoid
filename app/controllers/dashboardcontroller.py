"""
Controller for static analysis dashboard
"""
import json
import os

from sqlalchemy import and_, or_, case
from flask import render_template, request, jsonify
from app import flask, db

from app.models.application import (MobileApplication,
                                    MobileFile, MobileFileFinding)


@flask.route("/vulns/<app_id>")
def get_static_code_vulns(app_id):
    """
    Get a list of file based vulnerabilities
    :param app_id:
    :return:
    """
    severity = None
    if request.args.get("severity", None):
        severity = request.args.get("severity")
    finding = None
    if request.args.get("finding", None):
        finding = request.args.get("finding")
    sub_stmt = db.session.query(
        MobileFile.id
    ).filter(MobileFile.application_id == app_id)
    stmt = db.session.query(
        MobileFileFinding
    ).filter(MobileFileFinding.file_id.in_(sub_stmt))
    if severity:
        if severity == "danger":
            stmt = stmt.filter(MobileFileFinding.severity == severity)
        if severity == "warning":
            stmt = stmt.filter(
                or_(
                    MobileFileFinding.severity == "danger",
                    MobileFileFinding.severity == "warning"
                )
            )
    if finding:
        stmt = stmt.filter(MobileFileFinding.name == finding)
    sort_keys = {"danger": 0, "warning": 1, "info": 2, "none": 3}
    order_by_case = case(
        *[(MobileFileFinding.severity == key, value) for key, value in sort_keys.items()]
    )
    stmt = stmt.order_by(order_by_case)
    groups = {}
    vulns = stmt.all()
    for vuln in vulns:
        if vuln.name not in groups:
            groups[vuln.name] = vuln.text

    return render_template('vulnerabilities.html', vulns=vulns, app_id=app_id, groups=groups)


@flask.route("/vulns/<vuln_id>/info")
def get_vuln_information(vuln_id):
    """
    Get a single static code vulnerability and combine it with the file data
    :param vuln_id:
    :return:
    """
    get_vuln = MobileFileFinding.query.filter(
        MobileFileFinding.id == vuln_id
    )
    if not get_vuln.count():
        return jsonify({"result": False})
    vuln_data = get_vuln.first()
    file_data = MobileFile.query.filter(
        and_(
            MobileFile.name == vuln_data.filename,
            MobileFile.application_id == vuln_data.application_id
        )
    ).first()
    min_line = 5
    try:
        file_lines = file_data.data.decode().split("\n")
        get_line_min = vuln_data.file_line - min_line
        get_line_min = max(get_line_min, 0)
        out_lines = "\n".join(file_lines[get_line_min:vuln_data.file_line+min_line])
    except UnicodeDecodeError:
        out_lines = f"{vuln_data.filename}:{vuln_data.file_line}"
    except ValueError:
        out_lines = f"{vuln_data.filename}:{vuln_data.file_line}"

    return jsonify({
        "result": True,
        "vuln": vuln_data.readable(),
        "text": out_lines
    })


@flask.route("/dashboard/<app_id>")
def get_apk_dashboard(app_id):
    """
    Show application specific metadata and information
    Also includes a detailed list of Android permissions
    To update please run the script in the misc directory
    :param app_id:
    :return:
    """
    application = MobileApplication.query.filter(MobileApplication.checksum == app_id)
    application_data = application.first()

    get_meta = MobileFile.query.filter(
        MobileFile.application_id == app_id
    ).filter(
        MobileFile.name == "meta.json"
    )
    contents = None
    if get_meta.count():
        metadata = get_meta.first()
        contents = metadata.data.decode()
        contents = json.loads(contents)

    output_perm = {}
    perm_list = os.path.join(
        os.path.dirname(__file__),
        f"..{os.path.sep}",
        f"..{os.path.sep}",
        "misc",
        "android_permissions.json"
    )
    with open(perm_list, 'r', encoding="utf-8") as inf_json:
        output_perm = json.load(inf_json)

    sort_keys = {"danger": 0, "warning": 1, "info": 2, "none": 3}
    order_by_case = case(
        *[(MobileFileFinding.severity == key, value) for key, value in sort_keys.items()]
    )

    sub_stmt = db.session.query(
        MobileFile.id
    ).filter(MobileFile.application_id == app_id)
    stmt = db.session.query(
        MobileFileFinding
    ).filter(MobileFileFinding.file_id.in_(sub_stmt)).order_by(order_by_case)

    unique_findings = {}
    severities = {
        "none": 0,
        "info": 0,
        "warning": 0,
        "danger": 0,
        "total": 0
    }
    map_severity = {}
    for finding in stmt.all():
        if finding.text in unique_findings:
            unique_findings[finding.text] += 1
        else:
            map_severity[finding.text] = finding.severity
            unique_findings[finding.text] = 1
            severities[finding.severity] += 1
            severities["total"] += 1

    for entry in ["none", "info", "warning", "danger"]:
        if not severities.get("total", None):
            severities[f"perc_{entry}"] = 0
        else:
            severities[f"perc_{entry}"] = severities[entry] / severities["total"] * 100

    return render_template(
        "dashboard.html",
        application=application_data,
        app_id=app_id,
        meta=contents,
        perms=output_perm,
        findings=unique_findings,
        severities=severities,
        map_severity=map_severity
    )
