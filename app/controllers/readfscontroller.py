"""
Module to read files stored by the static analyser
"""
import json
import string

from flask import (render_template, request, jsonify)
from app import flask
from ext.frida_utils import auto_method_patcher

from app.models.application import MobileFile, MobileFileFinding


def strings(data: bytes, min_string_length=4):
    """
    Python equivalent of the Linux strings command
    :param data:
    :param min_string_length:
    :return:
    """
    output = []
    result = ""
    char_pool = [ord(x) for x in string.printable]
    for character in data:
        if character in char_pool:
            result += chr(character)
            continue
        if len(result) >= min_string_length:
            output.append(result)
        result = ""
    if len(result) >= min_string_length:
        output.append(result)
    return output


@flask.route("/files/<app_id>", methods=["GET"])
def get_folder_structure(app_id):
    """
    Get a list of all files stored in the database
    Includes some search options
    :param app_id:
    :return:
    """
    get_apk_data = MobileFile.query.filter(MobileFile.application_id == app_id)
    search_type = request.args.get("search_type", default=None)
    keyword = request.args.get("keyword", default=None)
    all_entries = get_apk_data.all()
    selected_vuln = None
    if request.args.get("vuln", None):
        selected_vuln = MobileFileFinding.query.filter(
            MobileFileFinding.id == request.args.get("vuln")
        )
        if selected_vuln.count() > 0:
            selected_vuln = selected_vuln.first()
        else:
            selected_vuln = None
    tree = []
    for file_entry in all_entries:
        if file_entry.mime == "application/x-empty":
            continue
        if search_type and keyword:
            if search_type == "classes":
                if f"class {keyword}".encode() not in file_entry.data:
                    continue
            if search_type == "code":
                if keyword.encode() not in file_entry.data:
                    continue
            if search_type == "resources":
                if not file_entry.name.startswith("resources/"):
                    continue
                if keyword.encode() not in file_entry.data:
                    continue
        tree.append(file_entry.name)
    return render_template(
        "filesystem.html",
        fs=json.dumps(tree),
        app_id=app_id,
        selected_vuln=selected_vuln
    )


@flask.route("/get_file/<app_id>", methods=["GET"])
def get_raw_file(app_id):
    """
    Get a single file from the database
    Blocks binary files (or corrupted ones)
    :param app_id:
    :return:
    """
    selected = request.args.get("file")
    get_apk_data = MobileFile.query.filter(
        MobileFile.application_id == app_id
    ).filter(MobileFile.name == selected)

    entry = get_apk_data.first().readable()

    try:
        entry["data"] = entry["data"].decode()
        try:
            if entry["data"].startswith("{") or entry["data"].startswith("["):
                entry["data"] = json.dumps(
                    json.loads(entry["data"]),
                    indent=4,
                    sort_keys=False
                )
        except ValueError:
            pass
    except UnicodeDecodeError:
        data_out = "This is a binary file, non-readable sections were removed\n\n"
        data_out += "\n".join(strings(entry["data"]))
        entry["data"] = data_out

    return jsonify(entry)


@flask.route("/get_strings/<app_id>", methods=["GET"])
def get_raw_file_strings(app_id):
    """
    Extract strings from a binary file
    :param app_id:
    :return:
    """
    selected = request.args.get("file")
    get_apk_data = MobileFile.query.filter(
        MobileFile.application_id == app_id
    ).filter(MobileFile.name == selected)

    entry = get_apk_data.first().readable()
    try:
        entry['data'] = strings(entry['data'])
    except ValueError:
        pass
    return jsonify(entry)


@flask.route("/get_patch_for/<app_id>", methods=["GET"])
def get_patch_options(app_id):
    """
    Attempt to automatically patch a Java method in a file
    :param app_id:
    :return:
    """
    selected = request.args.get("file")
    selected_method = request.args.get("method")
    get_apk_data = MobileFile.query.filter(
        MobileFile.application_id == app_id
    ).filter(MobileFile.name == selected)

    entry = get_apk_data.first().readable()
    try:
        entry["data"] = entry["data"].decode()
    except UnicodeDecodeError:
        entry["data"] = "This is a binary file and cannot be viewed."

    patch_data = auto_method_patcher(
        method=selected_method,
        file_data=entry["data"]
    )
    if patch_data:
        return jsonify({
            "status": True,
            "patch": patch_data
        })

    return jsonify({"status": False})
