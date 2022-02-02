"""
Class to check source files for security vulnerabilities
"""
import json
import re
import os
import logging
import xml.etree.ElementTree as ET

from ext.manifest import ManifestParser


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

    def check_manifest(self, root_location, apk_data):
        """
        Run some default checks on the manifest file
        :param root_location:
        :param apk_data:
        :return:
        """

        return ManifestParser(root_folder=root_location).parse(
            application_data=apk_data
        )

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
