"""
Framework specific checks for flutter applications
"""
import os
import string


def strings(filename, min_string_length=4):
    """
    Python equivalent of the Linux strings command
    :param filename:
    :param min_string_length:
    :return:
    """
    with open(filename, errors="ignore", encoding="utf-8") as read_flutter_bin:
        result = ""
        for character in read_flutter_bin.read():
            if character in string.printable:
                result += character
                continue
            if len(result) >= min_string_length:
                yield result
            result = ""
        if len(result) >= min_string_length:
            yield result


class FlutterStrategy:
    """
    Class for finding useful strings in Flutter applications
    """
    root_dir = None
    flutter_dir = None
    output = {}
    name = "Flutter"

    def __init__(self, application_root):
        self.root_dir = application_root

    def detect(self):
        """
        Wait. dis flutter?
        :return:
        """
        self.flutter_dir = os.path.join(
            self.root_dir,
            "resources",
            "assets",
            "flutter_assets"
        )
        return os.path.exists(self.flutter_dir)

    def check_fs(self):
        """
        Check for debug kernel and release one
        :return:
        """
        debug_file = os.path.join(self.flutter_dir, "kernel_blob.bin")
        if os.path.exists(debug_file):
            self.output["kernel_blob"] = "\n".join(strings(debug_file, min_string_length=6))
        release_file = os.path.join(self.flutter_dir, "isolate_snapshot_data")
        if os.path.exists(release_file):
            self.output["kernel"] = "\n".join(strings(release_file, min_string_length=6))
