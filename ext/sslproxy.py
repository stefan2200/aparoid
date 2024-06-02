#!/usr/bin/env python
"""
No more custom shit!!
"""
import sys
import time
import os
import subprocess
import psutil

root_app = os.path.join(
    os.path.dirname(__file__),
    f"..{os.path.sep}"
)
sys.path.insert(0, root_app)

from config import Config

from ext.proxy_mitm import start_proxy


def proxy_server_runner(application_id):
    """
    Starter method for  the proxy
    :param application_id:
    :return:
    """

    print("Starting proxy server")
    start_proxy(
        application_id=application_id,
        proxy_port=Config.proxy_port,
        proxy_host=Config.proxy_host,
        use_kafka=Config.use_kafka and "--no-kafka" not in sys.argv,
        kafka_servers=Config.kafka_servers,
        cert_directory=Config.cert_directory,
    )


def async_start(app_id, use_kafka=True):
    """
    Start the proxy server
    Detaches the window in Windows
    :param app_id:
    :param use_kafka
    :return:
    """
    start_args = [sys.executable, __file__, app_id]
    if not use_kafka:
        start_args.append("--no-kafka")
    if os.name == 'nt':
        pid = subprocess.Popen(start_args)
    else:
        pid = subprocess.Popen(start_args)
    time.sleep(1)
    return pid.pid


def async_kill(app_id):
    """
    Kill the running proxy server
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
        except psutil.ZombieProcess:
            pass
    return False


def async_is_running(app_id):
    """
    Checks if the proxy server is already running
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
        except psutil.ZombieProcess:
            pass
    return False


if __name__ == '__main__':
    try:
        app_id = sys.argv[1]
        proxy_server_runner(app_id)
    except Exception as e:
        print("I crashed:")
        print(str(e))
        x = input("Press any key to exit.")
