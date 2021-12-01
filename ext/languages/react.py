import os
import jsbeautifier


class ReactNativeStrategy:
    """
    Class for finding useful strings in React applications
    """
    root_dir = None
    react_file = None
    output = {}

    def __init__(self, application_root):
        self.root_dir = application_root

    def detect(self):
        """
        Wait. dis React?
        :return:
        """
        self.react_file = os.path.join(
            self.root_dir,
            "resources",
            "assets",
            "index.android.bundle"
        )
        return os.path.exists(self.react_file)

    def check_fs(self):
        """
        DeObfuscate the react library
        :return:
        """
        attempt_decompile = ReactNativeNiceifier(file_location=self.react_file)
        self.output["react_source"] = attempt_decompile
        return attempt_decompile.beautify()


class ReactNativeNiceifier:
    """
    Class to de-obfuscate React native code
    Still pretty messy but yeah.. it is nicified :D
    """

    file_data = None

    def __init__(self, file_location):
        """
        Load the React native file
        :param file_location:
        """
        with open(file_location, mode='r', encoding='utf-8') as read_react:
            self.file_data = read_react.read()

    def beautify(self):
        """
        Run JavaScript beautifier
        :return:
        """
        opts = jsbeautifier.default_options()
        opts.indent_size = 4
        opts.max_preserve_newlines = 5
        opts.space_before_conditional = True
        opts.brace_style = "collapse"
        better = jsbeautifier.beautify(self.file_data, opts=opts)
        return better
