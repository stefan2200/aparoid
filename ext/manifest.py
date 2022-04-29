"""
Module for parsing and analysing the Android Manifest
"""
import os
import re
import json


class ManifestParser:
    """
    Load all the used files
    """
    contents = ""
    findings = []
    finding_templates = {}
    manifest_filename = "resources/AndroidManifest.xml"
    root_folder = None

    def __init__(self, root_folder):
        """
        Load the manifest and template files
        """
        self.root_folder = root_folder
        get_manifest = os.path.join(
            root_folder,
            "resources",
            "AndroidManifest.xml"
        )
        if not os.path.exists(get_manifest):
            return

        with open(get_manifest, "r", encoding="utf-8") as read_manifest:
            self.contents = read_manifest.read()

        get_templates = os.path.join(
            os.path.dirname(__file__),
            f"..{os.path.sep}",
            "misc",
            "manifest.json"
        )
        with open(get_templates, "r", encoding="utf-8") as load_templates:
            self.finding_templates = json.load(load_templates)

    def parse(self, application_data):
        """
        Parse the contents and return a list of findings
        """
        findings = []
        min_sdk = self.check_min_sdk()
        if min_sdk:
            findings.append(min_sdk)

        check_backups = self.get_backups_allowed()
        if check_backups:
            findings.append(check_backups)

        for nsc_entry in self.check_nsc():
            findings.append(nsc_entry)

        to_check = [
            "activity", "service", "provider", "receiver"
        ]
        for check_type in to_check:
            for add_exported in self.get_exported_for(key=check_type):
                findings.append(add_exported)

        for check_signature in self.check_signatures(application_data):
            findings.append(check_signature)

        return findings

    def check_signatures(self, application_data):
        """
        Check the signature schemes for the application
        """
        findings = []
        signatures = application_data.get(
            "security", {}).get("signatures", {})
        sig_v1 = signatures.get("signed_v1", True)
        sig_v2 = signatures.get("signed_v2", True)
        sig_v3 = signatures.get("signed_v3", True)

        if sig_v1 and sig_v2 and sig_v3:
            return findings
        if sig_v1 and not sig_v2 and not sig_v3:
            create_finding = ManifestParser.finding_for(
                script=self.finding_templates.get("janus"),
                filename=f"{application_data['common']['package']}.apk",
                line_number=0,
                highlight=""
            )
            findings.append(create_finding)
        if sig_v1 and sig_v2 and not sig_v3:
            create_finding = ManifestParser.finding_for(
                script=self.finding_templates.get("no_v2"),
                filename=f"{application_data['common']['package']}.apk",
                line_number=0,
                highlight=""
            )
            findings.append(create_finding)
        return findings

    def check_nsc(self):
        """
        Checks the if a network security config exists and if it is secure
        """
        findings = []
        get_nsc = re.search(
            r'android:networkSecurityConfig="@xml/(.+?)"',
            self.contents
        )
        if not get_nsc:
            return findings
        get_path = f"{get_nsc.group(1)}.xml"
        nsc_base_path = os.path.join(
            "resources",
            "res",
            "xml",
            get_path
        )
        get_nsc = os.path.join(
            self.root_folder,
            nsc_base_path
        )
        if not os.path.exists(get_nsc):
            return findings

        with open(get_nsc, 'r', encoding="utf-8") as read_data:
            nsc_data = read_data.read()
        if 'cleartextTrafficPermitted="true"' in nsc_data:
            create_finding = ManifestParser.finding_for(
                script=self.finding_templates.get("nsc_cleartext"),
                filename=nsc_base_path,
                line_number=0,
                highlight="cleartextTrafficPermitted"
            )
            findings.append(create_finding)

        if '<certificates src="user"' in nsc_data:
            create_finding = ManifestParser.finding_for(
                script=self.finding_templates.get("nsc_usertrust"),
                filename=nsc_base_path,
                line_number=0,
                highlight="certificates"
            )
            findings.append(create_finding)
        return findings

    def get_backups_allowed(self):
        """
        Checks if backups are allowed
        """
        if 'android:allowBackup="true"' in self.contents:
            create_finding = ManifestParser.finding_for(
                script=self.finding_templates.get("backups_allowed"),
                filename=self.manifest_filename,
                line_number=0,
                highlight="allowBackup"
            )
            return create_finding

    def get_debuggable(self):
        """
        Checks if application is debuggable
        """
        if 'android:debuggable="true"' in self.contents:
            create_finding = ManifestParser.finding_for(
                script=self.finding_templates.get("debuggable"),
                filename=self.manifest_filename,
                line_number=0,
                highlight="debuggable"
            )
            return create_finding

    def get_exported_for(self, key):
        """
        Get list of exported entries
        :param key:
        """
        activities = []
        get_activity_string = re.findall(
            r'(?s)(<%s.+?name="(.+?)".+?)>' % key,
            self.contents
        )
        for get_activity in get_activity_string:
            if 'exported="true"' in get_activity[0]:
                create_finding = ManifestParser.finding_for(
                    script=self.finding_templates.get("exported"),
                    filename=self.manifest_filename,
                    line_number=0,
                    highlight=get_activity[1],
                    template_vars={"name": get_activity[1], "key": key}
                )
                activities.append(create_finding)
        return activities

    @staticmethod
    def get_data_from_sdk_version(sdk_version):
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

    def check_min_sdk(self):
        """
        Checks if the min sdk version still has support
        """
        get_version_group = re.search(
            r'android:minSdkVersion="(\d+)"',
            self.contents
        )
        if get_version_group:
            get_version = ManifestParser.get_data_from_sdk_version(
                get_version_group.group(1)
            )
            if get_version and get_version.get("supported") is False:
                template_prepare = {
                    "name": get_version.get("name"),
                    "min_version": get_version_group.group(1)
                }
                create_finding = ManifestParser.finding_for(
                    script=self.finding_templates.get("old_android"),
                    filename=self.manifest_filename,
                    line_number=0,
                    highlight="minSdkVersion",
                    template_vars=template_prepare
                )
                return create_finding

    @staticmethod
    def finding_for(script, filename, line_number, highlight, template_vars={}):
        """
        Returns a rinding object
        :param script:
        :param filename:
        :param line_number:
        :param highlight:
        :param template_vars:
        :return:
        """
        description = script.get("description")
        text = script.get("text")
        for t_key in template_vars:
            description = description.replace("{%s}" % t_key, template_vars[t_key])
            text = text.replace("{%s}" % t_key, template_vars[t_key])
        return {
            "key": script.get("key"),
            "text": text,
            "description": description,
            "search_type": script.get("search_type"),
            "filename": filename,
            "mobile_asvs": script.get("masvs"),
            "severity": script.get("severity", "INFO"),
            "line_number": line_number,
            "highlight": highlight
        }
