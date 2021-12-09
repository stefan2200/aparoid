"""
Static APK analysis routine
"""
import base64
import logging
import os
import threading
import json
import shutil
import magic

from ext.reporter import Reporter
from ext.apkutils import process
from ext.jadx_tools import JTool
from ext.security import LibrarySecurityScanner

from ext.languages import check_frameworks, get_framework_active
from ext.source_analyser import FileRunner


class ApplicationProcessor:
    """
    Process an application (runs in a Thread)
    """
    apk_checksum = None
    apk_location = None
    endpoint = None
    source_location = None
    sources_directory = "sources"
    options = []

    def __init__(self, endpoint, apk_checksum, apk_location, options=None):
        """
        Set the application information
        :param endpoint:
        :param apk_checksum:
        :param apk_location:
        """
        self.apk_location = apk_location
        self.endpoint = endpoint
        self.apk_checksum = apk_checksum
        self.source_location = os.path.join(self.sources_directory, self.apk_checksum)
        if options:
            self.options = options
        Reporter.push_log(
            endpoint=endpoint,
            key="info:analysis.start",
            application_id=self.apk_checksum,
            text=f"Starting analysis of {apk_location}"
        )

    def get_source_directory(self, apk_checksum):
        """
        Get application directory for a specific checksum
        :param apk_checksum:
        :return:
        """
        return os.path.join(self.sources_directory, apk_checksum)

    def run(self):
        """
        Start the analysis routine
        :return:
        """
        Reporter.push_log(
            endpoint=self.endpoint,
            key="info:sec.start",
            application_id=self.apk_checksum,
            text="Running passive security tests"
        )
        apk_data = process(apk_file=self.apk_location)
        apk_output = os.path.join(
            self.source_location,
            apk_data.get("common", {}).get("package", "base") + ".apk"
        )

        if not os.path.exists(self.sources_directory):
            os.mkdir(self.sources_directory)
        if not os.path.exists(self.source_location):
            os.mkdir(self.source_location)
        if "no-store" not in self.options:
            shutil.copyfile(self.apk_location, apk_output)

        Reporter.push_log(
            endpoint=self.endpoint,
            key="info:manifest.start",
            application_id=self.apk_checksum,
            text="Analysing AndroidManifest.xml"
        )

        Reporter.push_log(
            endpoint=self.endpoint,
            key="info:decompiler.start",
            application_id=self.apk_checksum,
            text="Running Jadx decompiler"
        )
        decompiler = JTool()
        decompiler_result = decompiler.invoke_jadx_on_apk(
            input_apk=self.apk_location,
            output_folder=self.source_location
        )
        if decompiler_result.get("code", 1):
            Reporter.push_log(
                endpoint=self.endpoint,
                key="error:decompiler.error",
                application_id=self.apk_checksum,
                text=decompiler_result.get("stdout")
            )
            Reporter.push_log(
                endpoint=self.endpoint,
                key="error:decompiler.error",
                application_id=self.apk_checksum,
                text="Exiting.."
            )
            return
        Reporter.push_log(
            endpoint=self.endpoint,
            key="info:decompiler.end",
            application_id=self.apk_checksum,
            text="Source code decompiled"
        )

        all_files = JTool.get_file_tree(self.source_location)
        icon = apk_data.get("common", {}).get("icon_data", None)
        if icon and icon.endswith(".png"):
            icon_location = os.path.join(
                self.source_location,
                icon
            )
            if os.path.exists(icon_location):
                Reporter.push_log(
                    endpoint=self.endpoint,
                    key="info:stored.icon",
                    application_id=self.apk_checksum,
                    text=f"Storing icon {icon}"
                )
                with open(icon_location, "rb") as read_icon:
                    apk_data["common"]["icon_data"] = base64.b64encode(
                        read_icon.read()
                    ).decode()
            icon_location = os.path.join(
                self.source_location,
                "resources",
                icon
            )
            if os.path.exists(icon_location):
                Reporter.push_log(
                    endpoint=self.endpoint,
                    key="info:stored.icon",
                    application_id=self.apk_checksum,
                    text=f"Storing icon {icon}"
                )
                with open(icon_location, "rb") as read_icon:
                    apk_data["common"]["icon_data"] = base64.b64encode(
                        read_icon.read()
                    ).decode()

        sec_output = os.path.join(self.source_location, "meta.json")
        with open(sec_output, "w") as write_sec:
            json.dump(apk_data, write_sec)

        binary_files = []
        for filename in all_files:
            if filename.endswith(".so"):
                binary_files.append(filename)
            if filename.endswith(".bin"):
                binary_files.append(filename)
            if filename.endswith(".dll"):
                binary_files.append(filename)
            basename = os.path.basename(filename)
            if "." not in basename:
                file_data = magic.from_file(filename)
                if "elf" in file_data.lower():
                    binary_files.append(filename)

        Reporter.push_log(
            endpoint=self.endpoint,
            key="info:binalysys.count",
            application_id=self.apk_checksum,
            text=f"Found {len(binary_files)} potential binary files"
        )
        Reporter.push_log(
            endpoint=self.endpoint,
            key="info:binalysys.start",
            application_id=self.apk_checksum,
            text="Checking binary file security"
        )
        binary_files_output = LibrarySecurityScanner.run_on_shared_objects(binary_files)
        if binary_files_output:
            Reporter.push_binary_result(
                endpoint=self.endpoint,
                application_id=self.apk_checksum,
                binaries=json.dumps(binary_files_output)
            )

        Reporter.push_log(
            endpoint=self.endpoint,
            key="info:frameworks.start",
            application_id=self.apk_checksum,
            text="Checking Framework files"
        )
        active_frameworks = get_framework_active(application_base_directory=self.source_location)
        if active_frameworks:
            Reporter.push_log(
                endpoint=self.endpoint,
                key="info:frameworks.found",
                application_id=self.apk_checksum,
                text=f"Framework(s) found: {', '.join(active_frameworks)}. "
                     "Running additional checks"
            )
            check_frameworks(application_base_directory=self.source_location)

        Reporter.push_log(
            endpoint=self.endpoint,
            key="info:file_pattern_analyser.start",
            application_id=self.apk_checksum,
            text="Checking source code for common issues. This might take a few minutes."
        )
        seen_findings = []
        src_checker = FileRunner()
        try:
            run_on_manifest = src_checker.check_manifest(self.source_location)
            if run_on_manifest:
                seen_findings = run_on_manifest
        except Exception as exception:
            logging.warning("Error checking Manifest data: %s", exception)
        part_files = len(all_files) / 5
        current_file = 0
        for source_file in all_files:
            current_file += 1
            if round(current_file) % round(part_files) == 0:
                files_todo = len(all_files)-current_file
                progress = round(current_file / len(all_files) * 100)
                Reporter.push_log(
                    endpoint=self.endpoint,
                    key="info:file_pattern_analyser.progress",
                    application_id=self.apk_checksum,
                    text=f"{progress}% {current_file} done {files_todo} todo"
                )
            with open(source_file, "rb") as read_source:
                result_checker = src_checker.run_on_file(
                    filename=source_file,
                    file_contents=read_source.read()
                )
                if result_checker:
                    for finding in result_checker:
                        if finding.get("search_type") == "once" and \
                                finding.get("key") in seen_findings:
                            continue
                        seen_findings.append(finding)
            vulns_file = os.path.join(
                self.source_location,
                "vulns.json"
            )
            with open(vulns_file, "w", encoding="utf-8") as write_vulns:
                json.dump(seen_findings, fp=write_vulns)

        Reporter.push_log(
            endpoint=self.endpoint,
            key="info:decompiler_flush.start",
            application_id=self.apk_checksum,
            text="Writing sources to database"
        )
        tmp_zip = os.path.join(self.sources_directory, self.apk_checksum)
        shutil.make_archive(tmp_zip, 'zip', self.source_location)

        Reporter.push_file(
            self.endpoint,
            filepath=f"{tmp_zip}.zip",
            application_id=self.apk_checksum
        )

        if "no-clean" not in self.options:
            Reporter.push_log(
                endpoint=self.endpoint,
                key="info:analysis.clean",
                application_id=self.apk_checksum,
                text="Cleaning directories"
            )

            shutil.rmtree(self.source_location)

        Reporter.push_log(
            endpoint=self.endpoint,
            key="info:analysis.end",
            application_id=self.apk_checksum,
            text="Completed"
        )


def threaded_processor(endpoint, apk_checksum, apk_location, options):
    """
    Starts the thread for the ApplicationProcessor class
    :param endpoint:
    :param apk_checksum:
    :param apk_location:
    :param options:
    :return:
    """
    local_dir = os.path.dirname(__file__)
    os.chdir(local_dir)
    try:
        ApplicationProcessor(
            endpoint,
            apk_checksum,
            apk_location,
            options
        ).run()
    except Exception as parse_exception:
        Reporter.push_log(
            endpoint=endpoint,
            key="error:parse_exception",
            application_id=apk_checksum,
            text=f"APK parse exception: {str(parse_exception)}"
        )
        print(f"APK parse exception: {str(parse_exception)}")


def initialize(endpoint, apk_checksum, apk_location, wait=False, options=None):
    """
    Actual thread start, the comment above was a lie
    :param endpoint:
    :param apk_checksum:
    :param apk_location:
    :param wait:
    :param options:
    :return:
    """
    start_thread = threading.Thread(
        target=threaded_processor,
        args=(endpoint, apk_checksum, apk_location, options)
    )
    start_thread.start()
    if wait:
        start_thread.join()
