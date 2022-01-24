"""
Module for decompressing Xamarin assemblies
"""

import os
import lz4.block


class XamarinStrategy:
    """
    Class for decompressing Xamarin assemblies
    """
    root_dir = None
    assemblies_dir = None
    output = {}
    hide_prefixes = [
        "Xamarin.",
        "Microsoft.",
        "System.",
        "Mono."
    ]
    name = "Xamarin"

    def __init__(self, application_root):
        self.root_dir = application_root

    def detect(self):
        """
        Wait. dis Xamarin?
        :return:
        """
        self.assemblies_dir = os.path.join(
            self.root_dir,
            "resources",
            "assemblies"
        )
        if not os.path.exists(self.assemblies_dir):
            return False
        dotnet_assemblies = [
            x for x in os.listdir(self.assemblies_dir) if x.endswith(".dll")
        ]
        return dotnet_assemblies

    def check_fs(self):
        """
        Check for Xamarin assemblies, hide common ones and decompress the rest
        :return:
        """
        dotnet_assemblies = [
            x for x in os.listdir(self.assemblies_dir) if x.endswith(".dll")
        ]
        for dotnet_file in dotnet_assemblies:
            if not self._should_check(dotnet_file):
                continue
            joined = os.path.join(
                self.assemblies_dir,
                dotnet_file
            )
            get_decompressed_data = XamarinStrategy.xamarin_decompress(joined)
            if get_decompressed_data:
                self.output[dotnet_file] = get_decompressed_data

    def _should_check(self, name):
        """
        Checks for common prefixes which should be ignored
        :param name:
        :return:
        """
        for hidden in self.hide_prefixes:
            if name.startswith(hidden):
                return False
        return True

    @staticmethod
    def xamarin_decompress(filename):
        """
        Decompress the .NET assembly
        :param filename:
        :return:
        """
        with open(filename, "rb") as file_header:
            header = file_header.read(8)
            if not header.startswith(b"XALZ"):
                return False
            file_data = file_header.read()

        try:
            file_data = lz4.block.decompress(file_data)
            return file_data
        except lz4.block.LZ4BlockError:
            return False
