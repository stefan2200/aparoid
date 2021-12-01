"""
Checks various frameworks
"""
import os

from ext.languages.react import ReactNativeStrategy
from ext.languages.flutter import FlutterStrategy
from ext.languages.xamarin import XamarinStrategy


def check_frameworks(application_base_directory):
    """
    Check application for commonly used frameworks like:
    - React Native
    - Flutter
    - Xamarin
    :param application_base_directory:
    :return:
    """
    builds = [ReactNativeStrategy, FlutterStrategy, XamarinStrategy]
    for library in builds:
        runner = library(application_root=application_base_directory)
        if runner.detect():
            runner.check_fs()
            output = runner.output
            decompiled_dir = os.path.join(
                application_base_directory,
                "decompiled"
            )
            if not os.path.exists(decompiled_dir):
                os.mkdir(decompiled_dir)
            for output_file in output:
                write_file = output[output_file]
                if isinstance(write_file, str):
                    write_file = write_file.encode()
                to_file = os.path.join(decompiled_dir, output_file)
                with open(to_file, mode='wb') as write_output:
                    write_output.write(write_file)
