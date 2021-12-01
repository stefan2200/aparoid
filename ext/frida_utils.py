"""
Library used for specific frida calls
"""
import json
import os.path
import sys
import time
import re
import threading
import frida

from kafka import KafkaProducer

root_app = os.path.join(
    os.path.dirname(__file__),
    f"..{os.path.sep}"
)
sys.path.insert(0, root_app)

from config import Config


class FridaUtils:
    """
    Wrapper for frida calls
    """

    @staticmethod
    def get_frida_version():
        """
        Return the version of the frida python module
        :return:
        """
        return frida.__version__

    @staticmethod
    def get_device_with_id(device_uuid):
        """
        Get all devices matching an ID
        :param device_uuid:
        :return:
        """
        devices = frida.enumerate_devices()
        for device in devices:
            if device.id == device_uuid:
                return device
        return None

    @staticmethod
    def has_process_for(processes, application):
        """
        Checks processes for a specific application name
        :param processes:
        :param application:
        :return:
        """
        for proc in processes:
            if proc.name in (application.identifier, application.name):
                return proc.pid
        return None

    @staticmethod
    def get_applications_for_device(device: frida.core.Device):
        """
        Get all installed applications on device (with process if it exists)
        :param device:
        :return:
        """
        if not device:
            return []
        applications = device.enumerate_applications()
        output_applications = []
        processes = device.enumerate_processes()

        for application in applications:
            output_applications.append({
                "id": application.identifier,
                "name": application.name,
                "pid": FridaUtils.has_process_for(processes, application)
            })
        return output_applications

    @staticmethod
    def get_application(device: frida.core.Device, application_id):
        """
        Get application information with specific id
        :param device:
        :param application_id:
        :return:
        """
        if not device:
            return None
        applications = device.enumerate_applications()

        for application in applications:
            if application.identifier == application_id:
                return application
        return None

    @staticmethod
    def spawn_application(device: frida.core.Device, identifier: str, scripts=None):
        """
        Spawn application and hook scripts
        :param device:
        :param identifier:
        :param scripts:
        :return:
        """
        pid = device.spawn([identifier])
        device.resume(pid)
        if scripts:
            session = device.attach(pid)
            for script_data in scripts:
                script = session.create_script(script_data)
                script.load()
            time.sleep(1)
            session.detach()
        return pid

    @staticmethod
    def spawn_async(
            device: frida.core.Device,
            identifier: str,
            scripts=None, use_kafka=False):
        """
        Spawns frida in a thread (can get messages this way)
        :param device:
        :param identifier:
        :param scripts:
        :param use_kafka:
        :return:
        """
        thread = threading.Thread(
            target=FridaUtils.async_worker,
            args=(device, identifier, scripts, use_kafka)
        )
        thread.start()
        return thread

    @staticmethod
    def async_worker(device: frida.core.Device, identifier: str, scripts=None, use_kafka=True):
        """
        Start frida in a thread so kafka can work
        :param device:
        :param identifier:
        :param scripts:
        :param use_kafka:
        :return:
        """
        if use_kafka:
            producer = KafkaProducer(
                value_serializer=lambda m: json.dumps(m).encode('utf-8'),
                bootstrap_servers=Config.kafka_servers)

        def on_message(msg, _data):
            """
            Frida on_message event
            :param msg:
            :param _data:
            :return:
            """
            if use_kafka:
                try:
                    producer.send(f"frida-{identifier}", value=msg)
                except TypeError:
                    pass
            print(msg)
        pid = device.spawn([identifier])
        if scripts:
            session = device.attach(pid)
            if scripts:
                for script_data in scripts:
                    script = session.create_script(script_data)
                    script.on('message', on_message)
                    script.load()
        device.resume(pid)
        print("Frida is running asynchronously")
        sys.stdin.read()

    @staticmethod
    def get_scripts(ssl_unpin=False, debug_bypass=False, root_detect=False, scripts=None):
        """
        Load some default scripts
        :param ssl_unpin:
        :param debug_bypass:
        :param root_detect:
        :param scripts:
        :return:
        """
        if not scripts:
            scripts = []
        if ssl_unpin:
            script_location = os.path.join(
                os.path.dirname(__file__),
                "frida_scripts",
                "ssl-unpin.js"
            )
            with open(script_location, "r", encoding="utf-8") as unpin:
                scripts.append(unpin.read())
        if root_detect:
            script_location = os.path.join(
                os.path.dirname(__file__),
                "frida_scripts",
                "bypass-root-check.js"
            )
            with open(script_location, "r", encoding="utf-8") as bypass_root:
                scripts.append(bypass_root.read())
        if debug_bypass:
            script_location = os.path.join(
                os.path.dirname(__file__),
                "frida_scripts",
                "emulator-check.js"
            )
            with open(script_location, "r", encoding="utf-8") as bypass_debug:
                scripts.append(bypass_debug.read())
        return FridaUtils.merge_scripts(scripts)

    @staticmethod
    def merge_scripts(scripts):
        """
        Combine multiple frida scripts into a single large one
        :param scripts:
        :return:
        """
        if not scripts:
            return scripts
        if len(scripts) == 1:
            return scripts
        combined = []
        for script in scripts:
            if 'setTimeout' in script:
                script = re.sub(r'setTimeout.+?\{', '', script, re.MULTILINE)
                last_bracket = script.rfind("}")
                script = script[:last_bracket]
            combined.append(script)
        return [f'setTimeout(function(){{ {"".join(combined)} }}, 0);']

    @staticmethod
    def kill_application(device: frida.core.Device, identifier: str):
        """
        Kill application with specific name
        :param device:
        :param identifier:
        :return:
        """
        try:
            pid = device.kill(identifier)
        except frida.ProcessNotFoundError:
            return True
        return pid


def auto_method_patcher(method, file_data):
    """
    Automatically extract a class / method from a file and create frida patch
    :param method:
    :param file_data:
    :return:
    """
    if "$" in method:
        method = method.replace("$", "\\$")
    get_method_re = re.search(
        r'(?:public|private)(?:final|static|protected|synchronized|\s)'
        r'*\s([\w<>_]+)\s({0})\s?\((.*?)\)'.format(method), file_data
    )
    if not get_method_re:
        return False

    def resolve_import(root_method):
        default_methods = ["String", "boolean", "int"]
        if root_method in default_methods:
            return root_method
        check_import = re.search(
            r'import\s(.+?\.{0});'.format(root_method), file_data
        )
        if check_import:
            return check_import.group(1)
        return None

    start_offset = get_method_re.span()[0]
    get_class = file_data[:start_offset]
    get_root_class = re.search(r'class\s([\w+_]+)(?!.*class\s)', get_class)
    get_package = re.search(r'package\s([\w+_\.]+);', get_class)

    method_to_patch = get_method_re.group(2).strip()
    method_type = get_method_re.group(1).strip()
    method_args = get_method_re.group(3).strip()

    method_class = get_root_class.group(1).strip()
    method_package = get_package.group(1).strip()
    arguments = []
    if "," in method_args:
        for sub_arg in method_args.split(","):
            arg_group = sub_arg.strip().split(" ")
            argument_type = resolve_import(arg_group[0])
            if not argument_type:
                argument_type = f"{method_package}.{arg_group[0]}"
            arguments.append(argument_type)
    elif " " in method_args.strip():
        arg_group = method_args.split(" ")
        argument_type = resolve_import(arg_group[0])
        if not argument_type:
            argument_type = f"{method_package}.{arg_group[0]}"
        arguments.append(argument_type)

    print("Generating patch instructions for:", method_package,
          method_class, method_type, method_to_patch, arguments)
    str_ok = f"{method_package}.{method_class}.{method_to_patch} found hooking"
    str_trg = f"{method_package}.{method_class}.{method_to_patch} hit"
    str_nope = f"{method_package}.{method_class}.{method_to_patch} not found"
    safe_class = re.sub(r'[\W0-9]+', '', method_class.lower())
    package = f"{method_package}.{method_class}"
    args_func = []
    args_quoted = []
    for arg in arguments:
        safe_arg = re.sub(r'[\W0-9]+', '', arg.lower())
        gen_arg = f"arg_{safe_arg}"
        if gen_arg in args_func:
            gen_arg = f"{gen_arg}_{len(args_func)}"
        args_func.append(gen_arg)
        args_quoted.append(f"'{arg}'")
    # TODO: handle lists
    frida_core = """
    setTimeout(function () {
        Java.perform(function () {    
            try{
                var GeneratedHook%s = Java.use("%s");
                send('[+] %s');
                GeneratedHook%s.%s.overload(%s).implementation = function(%s) {
                    send("--> %s");
                    return true;
                    // return false;
                    // return null;
                };
            } catch (err) {
                send('[-] %s');
            }
        });
    },0);
    """ % (safe_class, package, str_ok, safe_class, method_to_patch,
           ','.join(args_quoted), ', '.join(args_func), str_trg, str_nope)
    return frida_core
