"""
Controller that was previously used to run the processing async
That was a dumb idea..
"""
import json

import magic

from app import db
from app.models.application import MobileFile, MobileFileFinding, MobileApplication


def run_on_zip_queue(zip_data, app_id):
    """
    Process the zip file and findings
    Was running async but broke stuff so back to the default one :)
    :param zip_data:
    :param app_id:
    :return:
    """
    seen_findings = []
    for file in zip_data.namelist():
        if is_blacklisted(file):
            continue
        with zip_data.open(file, "r") as get_file:
            fh_data = get_file.read()
            push_file = MobileFile()
            push_file.name = file
            push_file.data = fh_data
            try:
                push_file.mime = magic.from_buffer(fh_data, mime=True)
            except magic.MagicException:
                push_file.mime = "unknown/x-unknown"
            push_file.application_id = app_id
            db.session.add(push_file)
            if file == "meta.json":
                parsed = json.loads(fh_data)
                current_app: MobileApplication = MobileApplication.query.filter(
                    MobileApplication.checksum == app_id
                ).first()
                current_app.version_name = parsed.get("common").get("version_name")
                current_app.version_code = parsed.get("common").get("version_code")
                current_app.icon = parsed.get("common").get("icon_data")
                db.session.commit()
    db.session.commit()

    with zip_data.open("vulns.json", "r") as read_vulns:
        vulns = json.load(read_vulns)
        for finding in vulns:
            if finding.get("search_type") == "once" and finding.get("key") in seen_findings:
                continue
            filename = finding.get("filename")

            filename = filename.replace("\\\\", "\\").replace("\\", "/")
            filename = filename.replace(f"sources/{app_id}/", "")
            if is_blacklisted(filename):
                continue
            try:
                mdf = MobileFileFinding()
                mdf.name = finding.get("key")
                mdf.text = finding.get("text")
                mdf.description = finding.get("description")
                mdf.application_id = app_id
                mdf.filename = filename
                mdf.file_line = finding.get("line_number")
                mdf.highlight = finding.get("highlight")
                mdf.severity = finding.get("severity")
                mdf.file_id = push_file.id
                mdf.mobile_asvs = finding.get("mobile_asvs")
                db.session.add(mdf)
                db.session.commit()
            except Exception as get_exception:
                print(f"Error adding finding: {str(get_exception)}")
    return True


def is_blacklisted(filename):
    """
    Block useless files from getting stored
    Mostly images
    :param filename:
    :return:
    """
    allowed_resources = [
        ".json", ".js", ".properties", ".sh",
        ".so", "AndroidManifest.xml", ".bin",
        ".html"
    ]

    blocked_sources = [
        "/android/",
        "/androidx/",
        "/R.java"
    ]

    if filename.startswith("resources/"):
        for allowed in allowed_resources:
            if filename.endswith(allowed):
                return False
        return True
    if filename.startswith("sources/"):
        for blocked in blocked_sources:
            if blocked in filename:
                return True
    return False
