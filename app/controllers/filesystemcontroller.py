"""
Controller for reading application files
Like the ones in the /data/data/some.app.idk location
"""
import os
import json
import secrets
import tarfile
import sqlite3
import pathlib
import magic
from flask import (render_template, request, jsonify, redirect, url_for, make_response)
from app import flask

from ext.adb import get_strategy_for


def strings(data: bytes, min_string_length=4):
    """
    Python equivalent of the Linux strings command
    :param data:
    :param min_string_length:
    :return:
    """
    output = []
    result = ""
    char_pool = [ord(x) for x in string.printable]
    for character in data:
        if character in char_pool:
            result += chr(character)
            continue
        if len(result) >= min_string_length:
            output.append(result)
        result = ""
    if len(result) >= min_string_length:
        output.append(result)
    return output


def get_file_tree(output_directory, basedir):
    """
    Get a root directory and build a tree like
    [/root/file1, /root/subdir/file2, ...]
    :param output_directory:
    :param basedir:
    :return:
    """
    if not os.path.exists(output_directory):
        return None
    files = []
    for recurse, _, file_list in os.walk(output_directory):
        for file in file_list:
            files.append(os.path.join(recurse, file))
    return [file.split(basedir)[1] for file in files]


class SQLiteParser:
    """
    Tbh I got this from someones GitHub
    I wish I could give him credit but the code was... bleh..
    """
    @staticmethod
    def dict_factory(cursor, row):
        """
        Build a key-value pair from the current row
        :param cursor:
        :param row:
        :return:
        """
        dict_f = {}
        for idx, col in enumerate(cursor.description):
            row_data = row[idx]
            if isinstance(row_data, bytes):
                row_data = row_data.decode()
            dict_f[col[0]] = row_data
        return dict_f

    @staticmethod
    def open_database(db_file_path):
        """
        Opens the database and returns the connection and custom row cursor
        :param db_file_path:
        :return:
        """
        connection = sqlite3.connect(db_file_path)
        connection.row_factory = SQLiteParser.dict_factory
        cursor = connection.cursor()
        return connection, cursor

    @staticmethod
    def query_table(table_name, db_file_path):
        """
        Queries a table using a SQL injection :-)
        :param table_name:
        :param db_file_path:
        :return:
        """
        conn, curs = SQLiteParser.open_database(db_file_path)
        conn.row_factory = SQLiteParser.dict_factory
        try:
            curs.execute(f"SELECT * FROM {table_name}")
            results = curs.fetchall()
        except sqlite3.Error:
            # Possibly malformed data or table
            results = {
                "error": "Data incomplete"
            }
            pass
        conn.close()
        return results

    @staticmethod
    def to_json(db_file_path):
        """
        Returns the database structure in a dictionary with:
        dict(table_name=Rows[dict(column=value, column2=value2), Row2..])
        :param db_file_path:
        :return:
        """
        connection, cursor = SQLiteParser.open_database(db_file_path)
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        table_data = {}
        for table_name in tables:
            results = SQLiteParser.query_table(table_name['name'], db_file_path)
            table_data[table_name['name']] = results
        connection.close()
        return table_data

    @staticmethod
    def to_ugly(file_input):
        """
        Takes the fancy output from the command above and returns..
        Well.. Something that looks (partially).. OK in Highlight.js
        :param file_input:
        :return:
        """
        out_str = ""
        for table_name in file_input:
            out_str += f"/* Table: {table_name} */\n"
            out_str += json.dumps(file_input[table_name], indent=4)
            out_str += "\n\n"
        return out_str


@flask.route("/dynamic/api/<device_type>/fs/<application>")
def read_fs_for(device_type, application):
    """
    See the steps below:
    - Create tar archive from the application directory
    - Save it to the SD card
    - Pull it using ADB
    - Remove it from SD card
    - Decompress it using Tarfile
    - Weird workaround for special path characters in Windows
    - Remove the local tar file
    - Hope everything went well

    :param device_type:
    :param application:
    :return:
    """
    adb_strategy = get_strategy_for(device_type=device_type)
    application_directory = f"/data/data/{application}/"
    dir_name = os.path.join(
        os.path.dirname(__file__),
        f"..{os.path.sep}",
        f"..{os.path.sep}",
        "cache"
    )
    if not os.path.exists(dir_name):
        os.mkdir(dir_name)
    filename = secrets.token_hex(nbytes=16)
    adb_strategy.runner.shell([
        "tar",
        "-zcvf",
        f"/sdcard/{filename}.tar",
        "-C",
        application_directory,
        "."
    ])
    adb_strategy.runner.pull(
        remote_file=f"/sdcard/{filename}.tar",
        local_file=os.path.join(dir_name, f"{filename}.tar")
    )
    adb_strategy.runner.shell([
        "rm",
        f"/sdcard/{filename}.tar"
    ])

    with tarfile.open(os.path.join(dir_name, f"{filename}.tar"),
                      mode="r", errorlevel=1) as decompress:
        extract_dir = os.path.join(dir_name, application)
        if not os.path.exists(extract_dir):
            os.mkdir(extract_dir)
        filenames = decompress.getmembers()
        for fname in filenames:
            try:
                decompress.extract(fname, extract_dir)
            except OSError:
                print(f"Error extracting {fname}")
    os.unlink(os.path.join(dir_name, f"{filename}.tar"))

    return redirect(url_for('get_filesystem', device_type=device_type, application=application))


@flask.route("/dynamic/<device_type>/fs/<application>")
def get_filesystem(device_type, application):
    """
    List the filesystem tree of the application
    Return an empty dir tree if not found
    :param device_type:
    :param application:
    :return:
    """
    dir_name = os.path.join(
        os.path.dirname(__file__),
        f"..{os.path.sep}",
        f"..{os.path.sep}",
        "cache"
    )
    extract_dir = os.path.join(dir_name, application)
    if not os.path.exists(extract_dir):
        os.mkdir(extract_dir)
    tree = get_file_tree(
        extract_dir,
        basedir=f"{extract_dir}{os.path.sep}"
    )
    tree = [t.replace("\\\\", "\\").replace("\\", "/") for t in tree]
    return render_template(
        'dynamic/filesystem.html',
        device_type=device_type,
        application=application,
        fs=json.dumps(tree)
    )


@flask.route("/dynamic/readfile/<application>")
def get_dynamic_file(application):
    """
    Get a local file using a GET parameter
    What could possibly go wrong :)

    Tried to fix path traversal..
    Fixed path traversal..
    Possibly still has path traversal

    :param application:
    :return:
    """
    selected_file = request.args.get("file", None)
    as_download = request.args.get("download", None)
    dir_name = os.path.join(
        os.path.dirname(__file__),
        f"..{os.path.sep}",
        f"..{os.path.sep}",
        "cache"
    )
    extract_dir = os.path.join(dir_name, application)
    comb = os.path.join(extract_dir, selected_file)
    if os.name == 'nt':
        comb = comb.replace("/", "\\")
    try:
        pathlib.Path(extract_dir).joinpath(comb).resolve().relative_to(
            pathlib.Path(extract_dir).resolve())
    except ValueError:
        return jsonify({"data": "Path out of scope"})
    try:
        with open(comb, 'rb') as read_file:
            file_data = read_file.read()
    except FileNotFoundError:
        return jsonify({"data": "Unable to open file"})
    if as_download:
        return make_response((file_data, os.path.basename(comb)))
    mime = magic.from_file(comb)
    if "SQLite" in mime:
        file_data = SQLiteParser.to_ugly(SQLiteParser.to_json(comb))
    else:
        try:
            file_data = file_data.decode()
        except UnicodeDecodeError:
            new_data = "This is a binary file, non-readable sections were removed\n\n"
            new_data += "\n".join(strings(file_data))
            file_data = new_data
    try:
        file_data = json.dumps(
            json.loads(file_data),
            indent=4
        )
    except ValueError:
        pass
    return jsonify({"data": file_data, "mime": mime})
