"""
Controller for most of the dynamic analysis functionality
"""
import datetime
import logging
import os
import shutil
import validators


from app import flask, db
from flask import render_template, request, jsonify, url_for, redirect
from ext.adb import (ADBStrategy, get_device_information,
                     start_frida, screenshot,
                     install_certificate, remove_certificate,
                     do_proxy_stuff, check_root, download_package,
                     install_package)

from app.models.application import MobileApplication
from app.models.file import Screenshot
from config import Config
import ext.httpsec.http_processor
from ext.frida_utils import FridaUtils

from ext.sslproxy import (async_start, async_kill)


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


@flask.route("/dynamic", methods=["GET"])
def dynamic_result_overview():
    """
    Load the initial dynamic overview dashboard
    :return:
    """
    return render_template("dynamic/default.html")


@flask.route("/dynamic/<device_type>", methods=["GET"])
def dynamic_rooted_setup(device_type):
    """
    Checks connected ADB devices and allows to connect to remote instances
    :param device_type:
    :return:
    """
    return render_template(
        "dynamic/writablesystem.html",
        device_type=device_type
    )


@flask.route("/dynamic/<device_type>/check/<device_uuid>", methods=["GET"])
def rooted_root_access(device_type, device_uuid):
    """
    Checks if the application with uuid has root access
    :param device_type:
    :param device_uuid:
    :return:
    """
    return render_template(
        "dynamic/rootcheck.html",
        device_type=device_type,
        device_uuid=device_uuid
    )


@flask.route("/dynamic/<device_type>/dashboard/<device_uuid>", methods=["GET"])
def dynamic_dashboard(device_type, device_uuid):
    """
    Load the dashboard and checks initial frida connection
    Also fetches basic device information
    :param device_type:
    :param device_uuid:
    :return:
    """
    frida_open = FridaUtils.get_device_with_id(device_uuid=device_uuid)
    frida_applications = []

    if frida_open:
        frida_applications = FridaUtils.get_applications_for_device(frida_open)

    additional_applications = []
    check_apps = MobileApplication.query.all()
    for check_app in check_apps:
        if check_app.get_apk(check_only=True):
            additional_applications.append(check_app.to_readable())

    return render_template(
        "dynamic/dashboard.html",
        device_type=device_type,
        device_uuid=device_uuid,
        device=get_device_information(device_uuid, device_type),
        frida_open=frida_open,
        frida_applications=frida_applications,
        local_frida_version=FridaUtils.get_frida_version(),
        additional_applications=additional_applications
    )


@flask.route("/dynamic/api/<device_uuid>/<device_type>/install_application/<application_id>", methods=["GET"])
def install_application_on_device(device_type, device_uuid, application_id):
    """
    Install an application from the static analyser
    :param device_type:
    :param device_uuid:
    :param application_id
    :return:
    """
    get_apk = MobileApplication.query.filter(
        MobileApplication.id == application_id
    ).first().get_apk(check_only=False)
    if not get_apk:
        return jsonify({
            "status": False,
            "error": "Unable to automatically install apk"
        })
    local_package_file = os.path.join(
        os.path.dirname(__file__),
        f"..{os.path.sep}",
        f"..{os.path.sep}",
        "ext",
        "sources",
        f"{get_apk.name}"
    )
    with open(local_package_file, "wb") as write_package:
        write_package.write(get_apk.data)
    logging.info(f"Installing package %s on %s", get_apk.name, device_uuid)
    result = install_package(
        device_type=device_type,
        device_uuid=device_uuid,
        store_location=os.path.abspath(local_package_file)
    )

    if not result:
        return jsonify({
            "status": False,
            "error": "Unable to install application on device."
        })

    return jsonify({
        "status": result
    })


@flask.route("/dynamic/api/cert/<device_type>/<device_uuid>/install", methods=["GET"])
def dynamic_install_cert(device_uuid, device_type):
    """
    Install the root CA on the device
    Supports all device types
    Magisk requires a reboot tho.
    :param device_uuid:
    :param device_type:
    :return:
    """
    install_certificate(
        device_uuid=device_uuid,
        selected_strategy=device_type,
        certificate_location=get_cert_location()
    )
    return jsonify({"status": True})


@flask.route("/dynamic/api/cert/<device_type>/<device_uuid>/remove", methods=["GET"])
def dynamic_remove_cert(device_uuid, device_type):
    """
    Remove the CA certificate from the device
    :param device_uuid:
    :param device_type:
    :return:
    """
    remove_certificate(
        device_uuid=device_uuid,
        selected_strategy=device_type,
        certificate_location=get_cert_location()
    )
    return jsonify({"status": True})


@flask.route("/dynamic/api/device_proxy/<device_type>/<device_uuid>/enable", methods=["GET"])
def dynamic_enable_device_proxy(device_uuid, device_type):
    """
    Set and enable the ADB reverse proxy on the device
    :param device_uuid:
    :param device_type:
    :return:
    """
    do_proxy_stuff(
        device_uuid=device_uuid,
        selected_strategy=device_type,
        disable=False
    )
    return jsonify({"status": True})


@flask.route("/dynamic/api/screenshot/<device_uuid>/<application_id>", methods=["GET"])
def dynamic_screenshot(device_uuid, application_id):
    """
    Set and enable the ADB reverse proxy on the device
    :param device_uuid:
    :param application_id:
    :return:
    """
    file_date = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

    file_friendly = f"screenshot_{file_date}.png"
    cache_dir = os.path.join(
        os.path.dirname(__file__),
        f"..{os.path.sep}",
        f"..{os.path.sep}",
        "cache"
    )
    if not os.path.exists(cache_dir):
        os.mkdir(cache_dir)
    save_file = os.path.abspath(
        os.path.join(cache_dir, file_friendly)
    )
    logging.info("Saving screenshot to %s", save_file)
    screenshot(device_uuid=device_uuid, local_file=save_file)
    if not os.path.exists(save_file):
        return jsonify({"status": False})
    with open(save_file, mode="rb") as read_scr:
        save = Screenshot()
        save.application_id = application_id
        save.data = read_scr.read()
        db.session.add(save)
        db.session.commit()
    logging.info("Saved screenshot with id %d", save.id)
    return jsonify({"status": True, "file": save_file, "remote": save.id})


@flask.route("/dynamic/api/device_proxy/<device_type>/<device_uuid>/disable", methods=["GET"])
def dynamic_disable_device_proxy(device_uuid, device_type):
    """
    Remove and disable the ADB reverse proxy
    :param device_uuid:
    :param device_type:
    :return:
    """
    do_proxy_stuff(
        device_uuid=device_uuid,
        selected_strategy=device_type,
        disable=True
    )
    return jsonify({"status": True})


@flask.route("/dynamic/api/proxy/start/<application>", methods=["GET"])
def dynamic_start_proxy(application):
    """
    Start the async proxy server
    Pops open a new window on Windows
    Linux prints to the same terminal (can get quite messy)
    :param application:
    :return:
    """
    async_start(application)
    return jsonify({"status": True})


@flask.route("/dynamic/api/proxy/kill/<application>", methods=["GET"])
def dynamic_stop_proxy(application):
    """
    Stop the active proxy server
    :param application:
    :return:
    """
    return jsonify({"status": async_kill(application)})


@flask.route("/dynamic/api/collector/start/<application>", methods=["GET"])
def dynamic_start_collector(application):
    """
    Start the async collector server
    Pops open a new window on Windows
    Linux prints to the same terminal (can get quite messy)
    :param application:
    :return:
    """
    ext.httpsec.http_processor.async_start(application)
    return jsonify({"status": True})


@flask.route("/dynamic/api/collector/kill/<application>", methods=["GET"])
def dynamic_stop_collector(application):
    """
    Stops the active collector server
    :param application:
    :return:
    """
    return jsonify({"status": ext.httpsec.http_processor.async_kill(application)})


@flask.route("/dynamic/api/<device_type>/start_frida/<device_uuid>", methods=["GET"])
def start_frida_for_device(device_type, device_uuid):
    """
    Start the frida-server executable on the device
    Magisk should start it on boot so no worries
    :param device_type:
    :param device_uuid:
    :return:
    """
    result = start_frida(selected_strategy=device_type, device_uuid=device_uuid)
    return jsonify({
        "status": result
    })


@flask.route("/dynamic/api/check_device_attached", methods=["GET"])
def list_adb_devices():
    """
    Get a list of ADB devices
    There is probably a better way do this
    But I'm not here for your "you should do it like ..." comments
    If you can do it better then do it yourself :)
    :return:
    """
    adb_path = Config.adb_path
    if not adb_path:
        adb_path = shutil.which('adb')
    strategy = ADBStrategy(adb_path=adb_path)
    list_devices = strategy.run(["devices", "-l"])
    split = list_devices.stdout.decode().split("List of devices attached")
    if len(split) == 1:
        return jsonify({
            "status": False,
            "error": "Unable to enumerate connected devices"
        })
    device_tree = split[1].strip()
    if len(device_tree) == 0:
        return jsonify({
            "status": False,
            "error": "No devices attached"
        })
    device = device_tree.split("\n")
    output = {}
    for dev in device:
        split_group = dev.split(" ")
        output[split_group[0]] = " ".join(split_group[1:]).strip()
    return jsonify({
        "status": True,
        "devices": output
    })


@flask.route("/dynamic/api/<device_type>/su_check/<device_uuid>", methods=["GET"])
def adb_check_root_access_su(device_uuid, device_type):
    """
    Async check of root access
    Makes the the page doesn't break if a SU popup shows
    :param device_uuid:
    :param device_type:
    :return:
    """
    return jsonify({
        "status": check_root(device_uuid, device_type)
    })


@flask.route("/dynamic/api/reboot/<device_uuid>", methods=["GET"])
def adb_reboot(device_uuid):
    """
    Reboot the device using ADB
    :param device_uuid:
    :return:
    """
    adb_path = Config.adb_path
    if not adb_path:
        adb_path = shutil.which('adb')
    strategy = ADBStrategy(adb_path=adb_path)
    strategy.device = device_uuid
    strategy.run(["reboot"])
    return jsonify({
        "status": True
    })


@flask.route("/dynamic/api/remote_connect_device", methods=["GET"])
def adb_remote_connect():
    """
    Connect to a remote instance of ADB
    Like a Genymotion instance or something. Idk.
    :return:
    """
    adb_path = Config.adb_path
    if not adb_path:
        adb_path = shutil.which('adb')
    domain = request.args.get("domain")
    port = request.args.get("port")
    if domain != "localhost" and not validators.domain(domain) and not validators.ipv4(domain):
        return jsonify({
            "status": False,
            "error": f"{domain} is not a valid domain name or IP address"
        })
    if not port.isnumeric():
        return jsonify({
            "status": False,
            "error": f"{port} is not a valid port number"
        })
    strategy = ADBStrategy(adb_path=adb_path)
    connect_code = strategy.run(
        ["connect", f"{domain}:{port}"]
    )
    return jsonify({
        "status": connect_code.returncode == 0
    })


@flask.route("/dynamic/pwntool/<device_type>/<device_uuid>/static/<application>")
def to_static_analyser(device_uuid, device_type, application):
    """
    Download an application from the device and perform static analysis
    :param device_uuid:
    :param device_type:
    :param application:
    :return:
    """
    local_package_file = os.path.join(
        os.path.dirname(__file__),
        f"..{os.path.sep}",
        f"..{os.path.sep}",
        "ext",
        "sources",
        f"{application}.apk"
    )
    logging.info(f"Downloading package %s to %s", application, local_package_file)
    download_package(
        device_type=device_type,
        device_uuid=device_uuid,
        package_name=application,
        store_location=local_package_file
    )
    return redirect(url_for('process_apk_from_local', apk_name=f"{application}.apk"))
