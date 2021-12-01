"""
Module for starting mitmproxy
"""
import os
import logging


from mitmproxy.tools import cmdline, dump, main


def start_proxy(proxy_port=8088, no_default_options=False,
                extra_options=None, use_kafka=False,
                proxy_host="127.0.0.1", application_id="none",
                cert_directory="certs", kafka_servers=[]):
    """
    Start an instance of mitmproxy
    :param proxy_port:
    :param no_default_options:
    :param extra_options:
    :param use_kafka:
    :param proxy_host:
    :param application_id:
    :param cert_directory:
    :param kafka_servers:
    :return:
    """
    default_options = []
    if not no_default_options:
        default_options.extend([
            "-k",
            "--anticache",
            "--anticomp"
        ])
    if extra_options:
        if isinstance(extra_options, list):
            default_options.extend(extra_options)
        else:
            default_options.append(extra_options)
    get_ca_dir = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            f"..{os.path.sep}",
            cert_directory
        )
    )
    if not os.path.exists(get_ca_dir):
        logging.info("Creating certificates directory")
        os.mkdir(get_ca_dir)
    logging.info("Using %s as certificate directory", get_ca_dir)

    start_arguments = default_options
    start_arguments.extend(["--listen-port", str(proxy_port)])
    start_arguments.extend(["--listen-host", proxy_host])

    if use_kafka:
        get_kafka_interceptor = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                "proxy_mitm_kafka.py"
            )
        )
        start_arguments.extend([
            "--scripts",
            get_kafka_interceptor
        ])
    start_arguments.extend([
        "--set", f"confdir={get_ca_dir}",
        "--set", "websocket=false",
        "--set", f"kafka={','.join(kafka_servers)}",
        "--set", f"topic={application_id}"
    ])

    print(f"mitmproxy {' '.join(start_arguments)}")
    try:
        main.run(dump.DumpMaster, cmdline.mitmdump, start_arguments, {})
    except KeyboardInterrupt:
        pass
