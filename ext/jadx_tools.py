"""
Wrapper around the JADX decompiler
"""
import os
import stat
import subprocess
import logging
import zipfile

from urllib.request import urlretrieve


class JTool:
    """
    Wrapper class
    """
    jadx_version = "1.2.0"
    tools_directory = "tools"
    jadx_directory = "jadx"
    jadx_path_multi = ""
    is_windows = os.name == 'nt'

    def get_and_install_version(self):
        """
        Checks if a version of jadx is installed. If not download and install
        Supports both win and linux
        :return:
        """
        if not os.path.exists(self.tools_directory):
            logging.info("Tools directory does not exist, creating")
            os.mkdir(self.tools_directory)
        jadx_directory = os.path.join(self.tools_directory, self.jadx_directory)
        if not os.path.exists(jadx_directory):
            logging.info("Jadx directory does not exist, creating")
            os.mkdir(jadx_directory)
        absdir = os.path.join(jadx_directory, self.jadx_version)
        if os.path.exists(absdir):
            return os.path.join(absdir, "bin", "jadx.bat" if self.is_windows else "jadx")
        logging.info("Jadx version %s not found, installing", self.jadx_version)
        download_url = "https://github.com/skylot/jadx/releases/download/v{0}/jadx-{0}.zip".format(
            self.jadx_version, self.jadx_version)
        tmp_zip = os.path.join(jadx_directory, "jadx.zip")
        urlretrieve(download_url, tmp_zip)
        logging.info("Extracting jadx version %s", self.jadx_version)
        with zipfile.ZipFile(tmp_zip) as saved_zipfile:
            saved_zipfile.extractall(absdir)
        return os.path.join(absdir, "bin", "jadx.bat" if self.is_windows else "jadx")

    def invoke_jadx_on_apk(self, input_apk, output_folder):
        """
        Run JADX on the supplied apk file
        :param input_apk:
        :param output_folder:
        :return:
        """
        to_exec = self.get_and_install_version()
        command_args = [
            to_exec,
            "--output-dir", output_folder,
            input_apk
        ]

        try:
            extractor = subprocess.run(command_args, capture_output=True)
        except PermissionError:
            get_stat = os.stat(to_exec)
            os.chmod(to_exec, get_stat.st_mode | stat.S_IEXEC)
            logging.debug("Making Jadx executable")
            extractor = subprocess.run(command_args, capture_output=True)

        if extractor.returncode == 0:
            logging.info("Successfully decompiled file %s", input_apk)
        return {
            "code": extractor.returncode,
            "stdout": extractor.stdout.decode(),
            "stderr": extractor.stderr.decode()
        }

    @staticmethod
    def get_file_tree(output_directory):
        """
        Return the file tree of a specific directory
        :param output_directory:
        :return:
        """
        if not os.path.exists(output_directory):
            return None
        files = []
        for r, d, f in os.walk(output_directory):
            for file in f:
                files.append(os.path.join(r, file))
        return [file for file in files]

    @staticmethod
    def is_blacklisted(filename):
        """
        Blocks some files from getting stored on the remote server
        :param filename:
        :return:
        """
        if filename.endswith("AndroidManifest.xml"):
            return False
        if "resources/" in filename and filename.endswith(".json"):
            return False
        if "resources/" in filename and filename.endswith(".js"):
            return False
        if "resources/" in filename and filename.endswith(".properties"):
            return False
        if "resources/META-INF" in filename:
            return False
        if "resources/" in filename:
            return True
        return False
