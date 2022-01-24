"""
Controller for configuring, starting and interacting with Frida
"""
import logging
import os


from app import flask
from flask import render_template, request, jsonify, url_for, redirect
from ext.adb import (install_frida, do_proxy_stuff)

from config import Config
import ext.httpsec.http_processor
from ext.frida_utils import FridaUtils

from ext.sslproxy import async_is_running


def get_cert_location():
    """
    Checks if a root CA has already been created
    If so, return its path
    :return:
    """
    cert_location = os.path.realpath(os.path.join(
        os.path.dirname(__file__),
        f"..{os.path.sep}",
        f"..{os.path.sep}",
        Config.cert_location.replace("/", os.path.sep)
    ))
    if not os.path.exists(cert_location):
        return None
    return cert_location


@flask.route("/dynamic/api/<device_type>/install_frida/<device_uuid>", methods=["GET"])
def install_frida_for_device(device_type, device_uuid):
    """
    Run the frida installer script for the selected architecture
    :param device_type:
    :param device_uuid:
    :return:
    """
    result = install_frida(selected_strategy=device_type, device_uuid=device_uuid)
    logging.info("Installed frida on device")
    return jsonify({
        "status": result
    })


@flask.route("/dynamic/api/frida/<device_uuid>/start/<application>", methods=["GET"])
def frida_spawn_application(device_uuid, application):
    """
    Spawn an application with a specific identifier
    :param device_uuid:
    :param application:
    :return:
    """
    frida_open = FridaUtils.get_device_with_id(device_uuid=device_uuid)
    if not frida_open:
        return jsonify({
            "status": False,
            "error": "There was an error contacting frida, please refresh the page."
        })
    pid = FridaUtils.spawn_application(frida_open, application)
    return jsonify({
        "status": True,
        "pid": pid
    })


@flask.route(
    "/dynamic/api/frida/<device_type>/<device_uuid>/build_scripts/<application>",
    methods=["POST"]
)
def frida_build_scripts(device_uuid, device_type, application):
    """
    Build and combine a list of frida scripts
    Includes a couple of default ones
    :param device_uuid:
    :param device_type:
    :param application:
    :return:
    """
    logging.info("Building combined frida scripts for application %s", application)
    ssl_unpin = False
    root_bypass = False
    debug_bypass = False
    script_data = []
    if request.form.get("script_data", None):
        script_data = [request.form.get("script_data")]
    if request.form.get("ssl_unpin", None):
        ssl_unpin = True
    if request.form.get("root_bypass", None):
        root_bypass = True
    if request.form.get("debug_bypass", None):
        debug_bypass = True
    combined = FridaUtils.get_scripts(
        scripts=script_data,
        ssl_unpin=ssl_unpin,
        root_detect=root_bypass,
        debug_bypass=debug_bypass
    )
    tmp_out = os.path.join(
        os.path.dirname(__file__),
        f"..{os.path.sep}",
        f"..{os.path.sep}",
        "ext",
        "frida_scripts",
        f"frida-combined-{application}.js"

    )
    with open(tmp_out, "w", encoding="utf-8") as output_file:
        if not combined:
            combined = ""
        else:
            combined = combined[0]
        output_file.write(combined)

    return redirect(url_for(
        'frida_dashboard',
        device_uuid=device_uuid,
        device_type=device_type,
        application=application)
    )


@flask.route(
    "/dynamic/pwntool/<device_type>/<device_uuid>/dashboard/<application>",
    methods=["GET"]
)
def frida_dashboard(device_uuid, device_type, application):
    """
    The main dynamic dashboard
    Loads of fancy stuff
    :param device_uuid:
    :param device_type:
    :param application:
    :return:
    """
    frida_open = FridaUtils.get_device_with_id(device_uuid=device_uuid)
    frida_application = FridaUtils.get_application(frida_open, application_id=application)
    is_proxy_running = async_is_running(application)

    tmp_out = os.path.join(
        os.path.dirname(__file__),
        f"..{os.path.sep}",
        f"..{os.path.sep}",
        "ext",
        "frida_scripts",
        f"frida-combined-{application}.js"

    )
    frida_blob = None
    if os.path.exists(tmp_out):
        with open(tmp_out, "r", encoding="utf-8") as read_frida_script:
            frida_blob = read_frida_script.read()

    return render_template(
        'dynamic/pwntool.html',
        application=frida_application,
        device_type=device_type,
        device_uuid=device_uuid,
        proxy_running=is_proxy_running,
        collector_running=ext.httpsec.http_processor.async_is_running(application),
        certificate=get_cert_location(),
        proxy_enabled=do_proxy_stuff(
            device_uuid=device_uuid,
            selected_strategy=device_type,
            check_only=True
        ),
        frida_blob=frida_blob
    )


@flask.route("/dynamic/api/frida/<device_uuid>/kill/<application>", methods=["GET"])
def frida_kill_application(device_uuid, application):
    """
    Kill an application with a specific name
    Pretty weird that it is not using the identifier ?.?
    :param device_uuid:
    :param application:
    :return:
    """
    frida_open = FridaUtils.get_device_with_id(device_uuid=device_uuid)
    if not frida_open:
        return jsonify({
            "status": False,
            "error": "There was an error contacting frida, please refresh the page."
        })
    pid = FridaUtils.kill_application(frida_open, application)
    return jsonify({
        "status": True,
        "pid": pid
    })


@flask.route("/dynamic/api/spawn/<device_uuid>/<application>", methods=["GET"])
def spawn_frida_application(device_uuid, application):
    """
    Spawn an application on the device using frida and hook the combined scripts
    Scripts should be built before using
    :param device_uuid:
    :param application:
    :return:
    """
    frida_open = FridaUtils.get_device_with_id(device_uuid=device_uuid)
    use_async = request.args.get("async", False)

    if not frida_open:
        return jsonify({
            "status": False,
            "error": "There was an error contacting frida, please refresh the page."
        })
    tmp_out = os.path.join(
        os.path.dirname(__file__),
        f"..{os.path.sep}",
        f"..{os.path.sep}",
        "ext",
        "frida_scripts",
        f"frida-combined-{application}.js"

    )
    loaded_script = []
    if os.path.exists(tmp_out):
        with open(tmp_out, "r", encoding="utf-8") as read_frida_script:
            loaded_script.append(read_frida_script.read())
    thread = FridaUtils.spawn_async(
        device=frida_open,
        identifier=application,
        scripts=loaded_script,
        use_kafka=use_async
    )
    return jsonify({
        "status": True,
        "pid": thread.is_alive()
    })
