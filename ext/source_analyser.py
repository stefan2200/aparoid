"""
Class to check source files for security vulnerabilities
"""
import json
import re
import os
import logging
import xml.etree.ElementTree as ET


class FileRunner:
    """
    The class
    """
    scripts = []
    compiled_cache = {}

    def __init__(self):
        """
        Select the rule set for checking
        """
        script_data = os.path.join(
            os.path.dirname(__file__),
            "scripts",
            "file_scripts.json"
        )
        with open(script_data, "r", encoding="utf-8") as load_script:
            script_data = json.load(load_script)
        logging.info(
            "Loaded static ruleset %s version %s",
            script_data.get("name", "Unknown"),
            script_data.get("version", "")
        )
        self.scripts = script_data.get("matches", [])

    def get_regex(self, regex):
        """
        Caches regexes because they can get quite slow
        :param regex:
        :return:
        """
        if regex in self.compiled_cache:
            return self.compiled_cache[regex]
        self.compiled_cache[regex] = re.compile(regex)
        return self.compiled_cache[regex]

    def run_on_line(self, script, line_data):
        """
        Runs the checks on a single source code line
        :param script:
        :param line_data:
        :return:
        """
        if line_data == "":
            return None
        for pattern in script.get("patterns", []):
            search_type = pattern.get("search")
            return_group = pattern.get("group", 0)
            match = pattern.get("match")
            options = pattern.get("options", [])
            if "lowercase" in options:
                line_data = line_data.lower()
            if search_type == "contains" and match in line_data:
                return match
            if search_type == "regex":
                compiled = self.get_regex(match)
                result = compiled.search(line_data)
                if result:
                    return result.group(return_group)
            return None

    def finding_for(self, script, filename, line_number, highlight):
        """
        Returns a rinding object
        :param script:
        :param filename:
        :param line_number:
        :param highlight:
        :return:
        """
        return {
            "key": script.get("key"),
            "text": script.get("text"),
            "description": script.get("description"),
            "search_type": script.get("search_type"),
            "filename": filename,
            "mobile_asvs": script.get("masvs"),
            "severity": script.get("severity", "INFO"),
            "line_number": line_number,
            "highlight": highlight
        }

    def is_allowed_type(self, file_types, filename):
        """
        Check if the filename can be processed
        :param file_types:
        :param filename:
        :return:
        """
        for match in file_types.split(","):
            match = match.strip()
            if match.startswith("!") and filename.endswith(match[1:]):
                return False
            if filename.endswith(match):
                return True
        return False

    def get_data_from_sdk_version(self, sdk_version):
        """
        Get data from Android sdk version
        :param sdk_version:
        :return:
        """
        get_version_file = os.path.join(
            os.path.dirname(__file__),
            f"..{os.path.sep}",
            "misc",
            "android_versions.json"
        )
        if not os.path.exists(get_version_file):
            print("Android version file not found, ignoring sdk version")
        with open(get_version_file, "r", encoding="utf-8") as read_file:
            get_versions = json.load(fp=read_file)
        if sdk_version in dict(get_versions):
            return get_versions[sdk_version]
        return None

    def check_manifest(self, root_location):
        """
        Run some default checks on the manifest file
        :param root_location:
        :return:
        """
        get_manifest = os.path.join(
            root_location,
            "resources",
            "AndroidManifest.xml"
        )
        if not os.path.exists(get_manifest):
            return None
        manifest_name = "resources/AndroidManifest.xml"
        findings = []
        with open(get_manifest, "r", encoding="utf-8") as read_manifest:
            # remove namespaces because they are annoying
            without_ns = re.sub(r'\sandroid:', ' ', read_manifest.read())
            tree = ET.ElementTree(ET.fromstring(without_ns))
        root_node = tree.getroot()

        get_sdk = root_node.find("uses-sdk")
        min_version = get_sdk.get("minSdkVersion", None)
        if min_version:
            check_version = self.get_data_from_sdk_version(min_version)
            if check_version and check_version.get("supported") is False:
                script = {
                    "key": "ext.manifest",
                    "text": "Old Android versions supported",
                    "description": f"{check_version.get('name')} (SDK {min_version}) "
                                   f"is the minimal requirement for the application. "
                                   f"This version is unsupported and may "
                                   f"introduce additional security risks.",
                    "search_type": "single",
                    "severity": "warning",
                    "masvs": None
                }
                finding = self.finding_for(
                    script=script,
                    filename=manifest_name,
                    highlight=f"android:minSdkVersion={min_version}",
                    line_number=0
                )
                findings.append(finding)

        get_application = root_node.find("application")
        get_allow_backup = get_application.get("allowBackup", None)
        if get_allow_backup and "true" in get_allow_backup:
            script = {
                "key": "ext.allow_backup",
                "text": "Cloud backups enabled",
                "description": "The application has allowBackup enabled. "
                               "This options allows the application "
                               "data to be backed-up using cloud backups.",
                "search_type": "single",
                "severity": "warning",
                "masvs": None
            }
            finding = self.finding_for(
                script=script,
                filename=manifest_name,
                highlight="android:allowBackup=true",
                line_number=0
            )
            findings.append(finding)

        get_allow_debug = get_application.get("debuggable", None)
        if get_allow_debug and "true" in get_allow_debug:
            script = {
                "key": "ext.debuggable_enabled",
                "text": "Debuggable application",
                "description": "The application has debuggable enabled. "
                               "This options allows the application to "
                               "be remotely debugged on non-rooted devices.",
                "search_type": "single",
                "severity": "warning",
                "masvs": None
            }
            finding = self.finding_for(
                script=script,
                filename=manifest_name,
                highlight="android:debuggable=true",
                line_number=0
            )
            findings.append(finding)

        get_activities = get_application.findall("activity")
        for activity in get_activities:
            if "true" in activity.attrib.get("exported", ""):
                script = {
                    "key": "ext.exported_activity",
                    "text": "Exported activity",
                    "description": f"The application is exporting the following activity: "
                                   f"{activity.attrib.get('name')}. This activity can be opened"
                                   f" from any application on the device "
                                   f"and might increase attack surface.",
                    "search_type": "multi",
                    "severity": "info",
                    "masvs": None
                }
                finding = self.finding_for(
                    script=script,
                    filename=manifest_name,
                    highlight=activity.attrib.get('name'),
                    line_number=0
                )
                findings.append(finding)

        get_services = get_application.findall("service")
        for service in get_services:
            if "true" in service.attrib.get("exported", ""):
                script = {
                    "key": "ext.exported_service",
                    "text": "Exported service",
                    "description": f"The application is exporting the following service: "
                                   f"{service.attrib.get('name')}. This activity can be opened"
                                   f" from any application on the device and "
                                   f"might increase attack surface.",
                    "search_type": "multi",
                    "severity": "info",
                    "masvs": None
                }
                finding = self.finding_for(
                    script=script,
                    filename=manifest_name,
                    highlight=service.attrib.get('name'),
                    line_number=0
                )
                findings.append(finding)

        return findings

    def run_on_file(self, filename: str, file_contents: bytes):
        """
        Run all scripts on a complete file
        :param filename:
        :param file_contents:
        :return:
        """
        results = []
        try:
            # dropping non-text files
            file_contents = file_contents.decode()
        except UnicodeDecodeError:
            return None

        line_counter = 0
        for file_line in file_contents.split("\n"):
            line_counter += 1
            file_line = file_line.strip()
            for script in self.scripts:
                hide_types = script.get("search_location", None)
                if hide_types and not self.is_allowed_type(hide_types, filename):
                    continue
                match_result = self.run_on_line(script=script, line_data=file_line)
                if not match_result:
                    continue
                finding = self.finding_for(
                    script=script,
                    line_number=line_counter,
                    filename=filename,
                    highlight=match_result
                )
                results.append(finding)
        return results
