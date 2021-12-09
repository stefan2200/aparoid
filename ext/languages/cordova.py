import os
import jsbeautifier


def get_files(root_directory):
    """
    Get a list of files
    """
    if not os.path.exists(root_directory):
        return None
    files = []
    for r, d, f in os.walk(root_directory):
        for file in f:
            files.append(os.path.join(r, file))
    return [file for file in files]


class CordovaStrategy:
    """
    Class for finding and deobfuscating Cordova JavaScript files
    """
    root_dir = None
    cordova_directory = None
    output = {}
    name = "Cordova"

    def __init__(self, application_root):
        self.root_dir = application_root

    def detect(self):
        """
        Check if the framework is Cordova
        :return:
        """
        self.cordova_directory = os.path.join(
            self.root_dir,
            "resources",
            "assets",
            "cordova"
        )
        if os.path.exists(self.cordova_directory):
            return self.cordova_directory

        self.cordova_directory = os.path.join(
            self.root_dir,
            "resources",
            "assets",
            "www"
        )
        if os.path.exists(self.cordova_directory):
            return self.cordova_directory
        return None

    def check_fs(self):
        """
        DeObfuscate cordova libraries
        :return:
        """
        fs_files = get_files(self.cordova_directory)
        for filename in fs_files:
            attempt_decompile = CordovaStrategy.beautify(file_location=filename)
            if attempt_decompile:
                with open(filename, mode="w", encoding="utf-8") as better:
                    better.write(attempt_decompile)
        return True

    @staticmethod
    def beautify(file_location):
        """
        Run JavaScript beautifier
        :return:

        """
        try:
            with open(file_location, mode='r', encoding='utf-8') as read_cordova_file:
                file_data = read_cordova_file.read()
                opts = jsbeautifier.default_options()
                opts.indent_size = 4
                opts.max_preserve_newlines = 5
                opts.space_before_conditional = True
                opts.brace_style = "collapse"
                better = jsbeautifier.beautify(file_data, opts=opts)
                return better
        except UnicodeError:
            return None
