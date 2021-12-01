"""
Messy wrapper for ADB commands
"""
import shutil
import subprocess
import hashlib
import base64
import logging
import time
import OpenSSL

from ext import frida_installer

from config import Config


class Utils:
    """
    Some utilities which I moved to this class
    Not sure why
    """
    @staticmethod
    def load_certificate(input_file):
        """
        Allows multiple certificate formats to be used
        Like the Burp Suite one and stuff
        :param input_file:
        :return:
        """
        with open(input_file, "rb") as input_cert:
            loader = input_cert.read()
        try:
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, loader)
            return cert
        except OpenSSL.crypto.Error:
            loader = base64.b64decode(loader)
            cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, loader)
            return cert

    @staticmethod
    def get_signature(cert: OpenSSL.crypto.X509):
        """
        Create the old subject hash from a x509 certificate
        TODO: check if this hash is correct
        :param cert:
        :return:
        """
        hd5 = hashlib.md5(cert.get_subject().der()).digest()
        part = (hd5[0] | (hd5[1] << 8) | (hd5[2] << 16) | hd5[3] << 24)
        ca_old_hash = hex(part).lstrip('0x')
        return f"{ca_old_hash}.0"


class ADBStrategy:
    """
    Common ADB strategy wrapper
    """
    adb_path = None
    device = None

    def __init__(self, adb_path):
        """
        Build the class and set adb_path
        :param adb_path:
        """
        self.adb_path = adb_path

    def shell(self, args):
        """
        Empty, pls override
        :param args:
        :return:
        """
        return

    def push(self, local_file, remote_file):
        """
        Empty, pls override
        :param local_file:
        :param remote_file:
        :return:
        """
        return

    def pull(self, local_file, remote_file):
        """
        Empty, pls override
        :param local_file:
        :param remote_file:
        :return:
        """
        return

    def check(self):
        """
        Don't call directly, crashes :)
        :return:
        """
        return b"(root)" in self.shell(["id"]).stdout

    def reverse_proxy(self, local="tcp:8088", adb="tcp:8088", remove=False):
        """
        Start a reverse port forward using adb
        Dunno why it is called proxy, should be reverse_forward
        :param local:
        :param adb:
        :param remove:
        :return:
        """
        if remove:
            return self.run([
                "reverse",
                "--remove",
                local
            ])
        return self.run([
            "reverse",
            local,
            adb
        ])

    def make_system_writable(self, as_ro=False):
        """
        Empty, pls override
        :param as_ro:
        :return:
        """
        return

    def run(self, arguments: list):
        """
        Run adb with arguments
        Additionally, device id may be specified to use multiple devices
        :param arguments:
        :return:
        """
        arguments.insert(0, self.adb_path)
        if self.device:
            arguments.insert(1, "-s")
            arguments.insert(2, self.device)

        logging.debug("ADB: %s", " ".join(arguments))
        proc = subprocess.run(
            executable=self.adb_path,
            args=arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        logging.debug(proc.stdout.decode())
        logging.debug(proc.stderr.decode())
        return proc


class ADBRootStrategy(ADBStrategy):
    """
    ADB strategy for most emulators
    """
    running_as_root = False
    system_rw = False

    def shell(self, args):
        """
        Run shell
        Requests adb root way too much
        :param args:
        :return:
        """
        if not self.running_as_root:
            get_result = self.run(["root"])
            if get_result.stdout and b"restarting adbd as root" in get_result.stdout:
                time.sleep(1)
            self.running_as_root = True
        call_args = ["shell"]
        call_args.extend(args)
        return self.run(call_args)

    def push(self, local_file, remote_file):
        """
        Push a local file to the connected device
        :param local_file:
        :param remote_file:
        :return:
        """
        if not self.running_as_root:
            self.run(["root"])
            self.running_as_root = True
        return self.run(["push", local_file, remote_file])

    def pull(self, local_file, remote_file):
        """
        Pull a file from the connected device
        :param local_file:
        :param remote_file:
        :return:
        """
        if not self.running_as_root:
            self.run(["root"])
            self.running_as_root = True
        return self.run(["pull", local_file, remote_file])

    def make_system_writable(self, as_ro=False):
        """
        Remount the system as r+w
        If adb remount fails it will attempt using the mount command
        :param as_ro:
        :return:
        """
        if self.system_rw:
            return
        logging.debug("Remount /system as writable")
        rcode = self.run(["remount"])
        if rcode.returncode != 0:
            self.shell(["mount", "-o", "rw,remount,rw", "/system"])
        self.system_rw = True


class ADBSystemRoot(ADBStrategy):
    """
    Same as ADBRootStrategy but without adb root/remount
    """
    system_rw = False

    def shell(self, args: list):
        """
        Shell stuff, see above
        :param args:
        :return:
        """
        run_args = ["shell", "su", "-c"]
        run_args.extend(args)
        return self.run(run_args)

    def push(self, local_file, remote_file):
        """
        Filesystem stuff, see above
        :param local_file:
        :param remote_file:
        :return:
        """
        working = self.run(["push", local_file, remote_file])
        if working.returncode == 0:
            return working
        self.shell(["touch", remote_file])
        self.shell(["chmod", "777", remote_file])
        working = self.run(["push", local_file, remote_file])
        return working

    def pull(self, local_file, remote_file):
        """
        Filesystem stuff, see above
        :param local_file:
        :param remote_file:
        :return:
        """
        working = self.run(["pull", remote_file, local_file])
        if working.returncode == 0:
            return working
        self.shell(["chmod", "+r", remote_file])
        working = self.run(["pull", remote_file, local_file])
        return working

    def make_system_writable(self, as_ro=False):
        """
        Remount /system as r+w
        Also remount r+o afterwards
        :param as_ro:
        :return:
        """
        if as_ro:
            if not self.system_rw:
                return
            logging.debug("Remount /system as read-only")
            self.shell(["mount", "-o", "ro,remount,ro", "/system"])
            self.system_rw = False
        else:
            if self.system_rw:
                return
            logging.debug("Remount /system as writable")
            self.shell(["mount", "-o", "rw,remount,rw", "/system"])
            self.system_rw = True


class ADBSystemlessRoot(ADBStrategy):
    """
    For Magisk root (no /system) access
    """
    def shell(self, args: list):
        """
        Shell stuff, see above
        :param args:
        :return:
        """
        run_args = ["shell", "su", "-c"]
        run_args.extend(args)
        return self.run(run_args)

    def push(self, local_file, remote_file):
        """
        Filesystem stuff, see above
        :param local_file:
        :param remote_file:
        :return:
        """
        working = self.run(["push", local_file, remote_file])
        if working.returncode == 0:
            return working
        self.shell(["touch", remote_file])
        self.shell(["chmod", "777", remote_file])
        working = self.run(["push", local_file, remote_file])
        return working

    def pull(self, local_file, remote_file):
        """
        Filesystem stuff, see above
        :param local_file:
        :param remote_file:
        :return:
        """
        working = self.run(["pull", remote_file, local_file])
        if working.returncode == 0:
            return working
        self.shell(["chmod", "+r", remote_file])
        working = self.run(["pull", remote_file, local_file])
        return working


class SystemRoot:
    """
    Class to do some stuff on Emulators and SU rooted devices
    """
    runner: ADBStrategy = None
    system_rw = False

    def __init__(self, adb_path, devel_image=False):
        """
        Set the ADB path and check if emulator
        :param adb_path:
        :param devel_image:
        """
        if not devel_image:
            self.runner = ADBSystemRoot(adb_path=adb_path)
        else:
            self.runner = ADBRootStrategy(adb_path=adb_path)

    def install_certificate(self, certificate_location):
        """
        Install a PEM certificate on the device
        :param certificate_location:
        :return:
        """
        cert = Utils.load_certificate(certificate_location)
        cert_hash = Utils.get_signature(cert)
        logging.info("Uploading certificate with hash %s", cert_hash)
        tmp_location = f"/sdcard/{cert_hash}"
        remote_location = f"/system/etc/security/cacerts/{cert_hash}"

        self.runner.make_system_writable()
        self.runner.push(certificate_location, tmp_location)
        self.runner.shell(["cp", tmp_location, remote_location])
        self.runner.shell(["chmod", "644", remote_location])
        logging.info("Deployed certificate with hash %s", cert_hash)
        self.runner.make_system_writable(as_ro=True)
        return True

    def remove_certificate(self, certificate_location):
        """
        Remove the certificate
        :param certificate_location:
        :return:
        """
        cert = Utils.load_certificate(certificate_location)
        cert_hash = Utils.get_signature(cert)
        logging.info("Removing certificate with hash %s",cert_hash)
        remote_location = f"/system/etc/security/cacerts/{cert_hash}"

        self.runner.make_system_writable()
        self.runner.shell(["rm", remote_location])
        logging.info("Removed certificate with hash %s", cert_hash)
        self.runner.make_system_writable(as_ro=True)
        return True

    def get_command_output(self, commands, default=None):
        """
        Run a command and return the output as a string
        :param commands:
        :param default:
        :return:
        """
        res = self.runner.shell(commands)
        if res.returncode == 0:
            return res.stdout.decode()
        return default


class SystemLessRoot:
    """
    Class for doing stuff on Magisk rooted devices
    """
    runner: ADBSystemlessRoot = None

    def __init__(self, adb_path):
        """
        Set the adb path
        :param adb_path:
        """
        self.runner = ADBSystemlessRoot(adb_path=adb_path)

    def install_certificate(self, certificate_location):
        """
        Install CA certificate on the device
        Requires Magisk module to use it in the system store
        :param certificate_location:
        :return:
        """
        cert = Utils.load_certificate(certificate_location)
        cert_hash = Utils.get_signature(cert)
        logging.info("Uploading certificate with hash %s", cert_hash)
        tmp_location = f"/sdcard/{cert_hash}"
        remote_location = f"/data/misc/user/0/cacerts-added/{cert_hash}"
        self.runner.push(certificate_location, tmp_location)
        self.runner.run(["shell", "su", "0", "-c", "mkdir", "/data/misc/user/0/cacerts-added"])
        self.runner.run(["shell", "su", "0", "-c", "cp", tmp_location, remote_location])
        self.runner.run(["shell", "su", "0", "-c", "chmod", "644", remote_location])
        logging.info("Deployed certificate with hash %s", cert_hash)
        return True

    def remove_certificate(self, certificate_location):
        """
        Remove the certificate
        :param certificate_location:
        :return:
        """
        cert = Utils.load_certificate(certificate_location)
        cert_hash = Utils.get_signature(cert)
        logging.info("Removing certificate with hash %s", cert_hash)
        remote_location = f"/data/misc/user/0/cacerts-added/{cert_hash}"

        self.runner.shell(["su", "0", "rm", remote_location])
        return True

    def get_command_output(self, commands, default=None):
        """
        Execute command and return output as a string
        :param commands:
        :param default:
        :return:
        """
        res = self.runner.shell(commands)
        if res.returncode == 0:
            return res.stdout.decode()
        return default


def get_device_information(device_uuid, selected_strategy):
    """
    Get some basic device information
    Should not crash (hopefully)
    :param device_uuid:
    :param selected_strategy:
    :return:
    """
    adb_path = Config.adb_path
    if not adb_path:
        adb_path = shutil.which('adb')
    if selected_strategy == "systemless":
        strategy = SystemLessRoot(adb_path=adb_path)
        strategy.runner.device = device_uuid
    else:
        strategy = SystemRoot(
            adb_path=adb_path,
            devel_image=selected_strategy == "emulated"
        )
        strategy.runner.device = device_uuid
    frida_running = False
    frida_version = None
    if selected_strategy != "systemless":
        check_frida = strategy.get_command_output(
            ["ls", "/data/local/tmp/frida-server"]
            , default=None
        )
        if check_frida:
            frida_version = strategy.get_command_output(
                ["/data/local/tmp/frida-server", "--version"]
                ,default=None
            )
            if frida_version:
                frida_version = frida_version.strip()
        check_frida_running = strategy.get_command_output(["ps"])
        frida_running = "frida-server" in check_frida_running
    return {
        "id": strategy.get_command_output(["id"]),
        "kernel": strategy.get_command_output(["uname", "-a"]),
        "proxy": strategy.get_command_output(["settings", "get", "global", "http_proxy"]),
        "arch": strategy.get_command_output(["getprop", "ro.product.cpu.abi"]),
        "sdk": strategy.get_command_output(["getprop", "ro.build.version.sdk"]),
        "android": strategy.get_command_output(["getprop", "ro.build.version.release"]),
        "applications": strategy.get_command_output(["pm", "list", "packages"]),
        "frida_installed": frida_version,
        "frida_running": frida_running
    }


def install_certificate(device_uuid, selected_strategy, certificate_location):
    """
    Install the certificate
    :param device_uuid:
    :param selected_strategy:
    :param certificate_location:
    :return:
    """
    adb_path = Config.adb_path
    if not adb_path:
        adb_path = shutil.which('adb')
    if selected_strategy == "systemless":
        strategy = SystemLessRoot(adb_path=adb_path)
        strategy.runner.device = device_uuid
    else:
        strategy = SystemRoot(
            adb_path=adb_path,
            devel_image=selected_strategy == "emulated"
        )
        strategy.runner.device = device_uuid
    strategy.install_certificate(certificate_location)


def do_proxy_stuff(device_uuid, selected_strategy, proxy_port=None,
                   proxy_host=None, disable=False, check_only=False):
    """
    Start and install the adb proxy
    Or disable..
    Or just check..
    Depends on the parameters
    :param device_uuid:
    :param selected_strategy:
    :param proxy_port:
    :param proxy_host:
    :param disable:
    :param check_only:
    :return:
    """
    adb_path = Config.adb_path
    if not adb_path:
        adb_path = shutil.which('adb')
    if selected_strategy == "systemless":
        strategy = SystemLessRoot(adb_path=adb_path)
        strategy.runner.device = device_uuid
    else:
        strategy = SystemRoot(
            adb_path=adb_path,
            devel_image=selected_strategy == "emulated"
        )
        strategy.runner.device = device_uuid
    if not proxy_port:
        proxy_port = Config.proxy_port
    if check_only:
        current_set = strategy.get_command_output(["settings", "get", "global", "http_proxy"])
        if not current_set or current_set.strip() in ["", ":0", "null"]:
            return False
        has_reverse = strategy.runner.run(["reverse", "--list"]).stdout.decode()
        if str(proxy_port) not in has_reverse:
            return False
        return current_set.strip()
    if not proxy_host:
        proxy_host = Config.proxy_host
        strategy.runner.reverse_proxy(
            local=f"tcp:{proxy_port}",
            adb=f"tcp:{proxy_port}",
            remove=True
        )
        if not disable:
            strategy.runner.reverse_proxy(
                local=f"tcp:{proxy_port}",
                adb=f"tcp:{proxy_port}",
                remove=False
            )
    if disable:
        strategy.runner.run(
            ["shell", "settings", "put", "global", "http_proxy", ":0"]
        )
    else:
        strategy.runner.run(
            ["shell", "settings", "put", "global", "http_proxy",
             f"{proxy_host}:{proxy_port}"]
        )
    return True


def get_strategy_for(device_type):
    """
    Get the correct strategy for a selected device type
    :param device_type:
    :return:
    """
    adb_path = Config.adb_path
    if not adb_path:
        adb_path = shutil.which('adb')
    if device_type == "systemless":
        return SystemLessRoot(adb_path=adb_path)
    if device_type == "emulated":
        return SystemRoot(adb_path=adb_path, devel_image=True)
    return SystemRoot(adb_path=adb_path, devel_image=False)


def remove_certificate(device_uuid, selected_strategy, certificate_location):
    """
    Remove a CA certificate from the device
    :param device_uuid:
    :param selected_strategy:
    :param certificate_location:
    :return:
    """
    adb_path = Config.adb_path
    if not adb_path:
        adb_path = shutil.which('adb')
    if selected_strategy == "systemless":
        strategy = SystemLessRoot(adb_path=adb_path)
        strategy.runner.device = device_uuid
    else:
        strategy = SystemRoot(
            adb_path=adb_path,
            devel_image=selected_strategy == "emulated"
        )
        strategy.runner.device = device_uuid
    strategy.remove_certificate(certificate_location)


def download_package(device_type, device_uuid, package_name, store_location):
    """
    Download a package with a given name
    :param device_type:
    :param device_uuid:
    :param package_name:
    :param store_location:
    :return:
    """
    strat = get_strategy_for(device_type)
    strat.runner.device = device_uuid
    get_apk = strat.get_command_output(
        ["pm", "path", package_name]
    ).strip().replace("package:", "")
    strat.runner.pull(remote_file=get_apk, local_file=store_location)


def install_package(device_type, device_uuid, store_location, second_attempt=False):
    """
    Install a locally available apk
    :param device_type:
    :param device_uuid:
    :param store_location:
    :param second_attempt:
    :return:
    """
    strat = get_strategy_for(device_type)
    strat.runner.device = device_uuid
    get_status = strat.runner.run([
        "install", store_location
    ])
    if get_status.returncode != 0:
        if second_attempt:
            return False
        return install_package(device_type, device_uuid, store_location, second_attempt=True)
    return True


def check_root(device_uuid, selected_strategy):
    """
    Check if the device is actually rooted
    :param device_uuid:
    :param selected_strategy:
    :return:
    """
    adb_path = Config.adb_path
    if not adb_path:
        adb_path = shutil.which('adb')
    if selected_strategy == "systemless":
        strategy = SystemLessRoot(adb_path=adb_path)
    else:
        strategy = SystemRoot(
            adb_path=adb_path,
            devel_image=selected_strategy == "emulated"
        )
        strategy.runner.device = device_uuid
    executed = strategy.get_command_output(["id"])
    if not executed:
        executed = strategy.get_command_output(["id"])
    return executed and "0(root)" in executed


def install_frida(device_uuid, selected_strategy):
    """
    Install the correct frida-server for the architecture of the device
    Wow :O
    :param device_uuid:
    :param selected_strategy:
    :return:
    """
    adb_path = Config.adb_path
    if not adb_path:
        adb_path = shutil.which('adb')
    if selected_strategy == "systemless":
        return False
    strategy = SystemRoot(
        adb_path=adb_path,
        devel_image=selected_strategy == "emulated"
    )
    strategy.runner.device = device_uuid
    architecture = strategy.get_command_output(["getprop", "ro.product.cpu.abi"])
    local_frida = frida_installer.FridaTools.install_for(architecture)
    strategy.runner.shell(["killall", "frida-server"])
    remote_frida = "/data/local/tmp/frida-server"
    strategy.runner.push(local_frida, remote_frida)
    return strategy.runner.shell(["chmod", "+x", remote_frida]).returncode == 0


def start_frida(device_uuid, selected_strategy):
    """
    Start the frida-server on the device
    :param device_uuid:
    :param selected_strategy:
    :return:
    """
    adb_path = Config.adb_path
    if not adb_path:
        adb_path = shutil.which('adb')
    if selected_strategy == "systemless":
        return False
    strategy = SystemRoot(
        adb_path=adb_path,
        devel_image=selected_strategy == "emulated"
    )
    strategy.runner.device = device_uuid
    remote_frida = "/data/local/tmp/frida-server"
    strategy.runner.shell(["killall", "frida-server"])
    strategy.runner.shell(["chmod", "755", remote_frida])
    strategy.runner.shell(["sh", "-c", '"cd /data/local/tmp/; ./frida-server -D &"'])
    check_frida_running = strategy.get_command_output(["ps"])
    frida_running = "frida-server" in check_frida_running
    return frida_running
