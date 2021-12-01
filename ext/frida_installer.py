"""
Helper script for frida
"""
import os
import lzma
import tempfile
import logging
import frida
import requests


logging.getLogger("urllib3").setLevel(logging.WARNING)


class FridaTools:
    """
    Various tools for frida
    """
    @staticmethod
    def get_arch(arch):
        """
        Return the correct architecture for the frida-server binary
        :param arch:
        :return:
        """
        if "arm64" in arch:
            return "arm64"
        if "armeabi" in arch:
            return "arm"
        if "x86_64" in arch:
            return "x86_64"
        if "x86" in arch:
            return "x86"
        return None

    @staticmethod
    def install_for(arch):
        """
        Install the frida-server for the local version + the remote architecture
        :param arch:
        :return:
        """
        device_arch = FridaTools.get_arch(arch)
        frida_version = frida.__version__
        frida_server = os.path.join(
            os.path.dirname(__file__),
            "tools",
            "frida"
        )
        if not os.path.exists(frida_server):
            os.mkdir(frida_server)
        out_file = f"{frida_version}-{device_arch}"

        install_location = os.path.join(frida_server, out_file)
        if os.path.exists(install_location):
            logging.debug("Using existing frida: %s", install_location)
            return install_location
        download_file = f"{frida_version}/frida-server-{frida_version}-android-{device_arch}.xz"
        version_url = f"https://github.com/frida/frida/releases/download/{download_file}"

        logging.info(f"Downloading frida server %s to %s", version_url, install_location)
        with tempfile.NamedTemporaryFile(suffix=".xz", delete=False) as write_file:
            write_file.write(requests.get(version_url).content)
        with open(install_location, "wb") as write_server:
            write_server.write(lzma.open(write_file.name, mode="rb").read())
        os.remove(write_file.name)
        return install_location
