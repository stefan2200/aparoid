"""
Controller to add the file checking json data
"""
import collections
import json
import os

from flask import render_template, request, redirect, url_for
from app import flask


class DatabaseController:
    """
    Class for doing database stuff
    """
    @staticmethod
    def get_database():
        """
        Get the current static vulnerability detection database
        :return:
        """
        db_file = os.path.join(
            os.path.dirname(__file__),
            f"..{os.path.sep}",
            f"..{os.path.sep}",
            "ext",
            "scripts",
            "file_scripts.json"
        )
        with open(db_file, "r", encoding="utf-8") as read_file:
            return json.load(read_file, object_pairs_hook=collections.OrderedDict)

    @staticmethod
    def update_database(new_data):
        """
        Update the database with a new entry
        Also creates a backup in the ext/scripts directory
        :param new_data:
        :return:
        """
        db_folder = os.path.join(
            os.path.dirname(__file__),
            f"..{os.path.sep}",
            f"..{os.path.sep}",
            "ext",
            "scripts"
        )
        old_file = DatabaseController.get_database()
        old_backup = os.path.join(
            db_folder,
            f"file_scripts-{old_file.get('version')}.json"
        )
        with open(old_backup, "w", encoding="utf-8") as backup_file:
            json.dump(old_file, fp=backup_file, sort_keys=False, indent=4)
        new_data["version"] = round(new_data["version"]+0.01, 2)
        new_file = os.path.join(
            db_folder,
            "file_scripts.json"
        )
        with open(new_file, "w", encoding="utf-8") as new_write:
            json.dump(new_data, fp=new_write, sort_keys=False, indent=4)

    @staticmethod
    def get_id_where_key(json_array, key):
        """
        Gets the index of an object with a specific key
        Used for in-place array replacement
        :param json_array:
        :param key:
        :return:
        """
        iter_num = 0
        for iter_item in json_array:
            if iter_item.get("key") == key:
                return iter_num
            iter_num += 1
        return None

    @staticmethod
    def get_where_key(json_array, key):
        """
        Returns an object matching a specific key
        :param json_array:
        :param key:
        :return:
        """
        for iter_item in json_array:
            if iter_item.get("key") == key:
                return iter_item
        return None

    @staticmethod
    def set_data_where_key(json_array, key, data, add_if_not_exists=False):
        """
        Sets the data with a specific key
        Can also append entries when they don't exist
        :param json_array:
        :param key:
        :param data:
        :param add_if_not_exists:
        :return:
        """
        set_entry = DatabaseController.get_id_where_key(json_array, key)
        if set_entry is None:
            if add_if_not_exists:
                json_array.append(data)
                return json_array
            return False
        json_array[set_entry] = data
        return json_array


@flask.route("/database/api/read/<entry>", methods=["GET"])
def get_database_entry_api(entry):
    """
    Get a single entry from the json database (api call)
    :param entry:
    :return:
    """

    handle = DatabaseController.get_database()
    get_id = DatabaseController.get_where_key(handle.get("matches"), entry)
    return json.dumps(get_id, sort_keys=False, indent=4)


@flask.route("/database/api/all", methods=["GET"])
def get_database_entries():
    """
    Gets all entries from the json database (api call)
    :return:
    """

    handle = DatabaseController.get_database()
    return json.dumps(handle, sort_keys=False, indent=4)


@flask.route("/database/read/<entry>", methods=["GET"])
def get_database_entry(entry):
    """
    Get a single entry from the json database
    :param entry:
    :return:
    """

    handle = DatabaseController.get_database()
    get_id = DatabaseController.get_where_key(handle.get("matches"), entry)
    return render_template("database/edit.html", entry=get_id)


@flask.route("/database/update", methods=["POST"])
def set_database_entry():
    """
    Updates a database entry
    Appends a new one if it doesn't exist
    :return:
    """
    start_match = 0
    matches = []
    while 1:
        get_match = request.form.get(f"match[{start_match}]", None)
        if not get_match:
            break
        get_pattern = request.form.get(f"pattern[{start_match}]", None)
        build_match = {"search": get_match, "match": get_pattern}
        get_group = request.form.get(f"group[{start_match}]", None)
        if get_group is not None and build_match == "regex":
            build_match["group"] = int(get_group)
        matches.append(build_match)
        start_match += 1

    structure = {
        "key": request.form.get("key").strip(),
        "text": request.form.get("text").strip(),
        "description": request.form.get("description").strip(),
        "mobile_asvs": request.form.get("mobile-asvs"),
        "search_type": request.form.get("search-type"),
        "severity": request.form.get("severity"),
        "search_location": request.form.get("search-location"),
        "patterns": matches

    }
    handle = DatabaseController.get_database()
    updated = DatabaseController.set_data_where_key(
        handle.get("matches"), key=structure.get("key"), data=structure,
        add_if_not_exists=True
    )
    handle["matches"] = updated
    DatabaseController.update_database(handle)
    return redirect(url_for('get_database'))


@flask.route("/database", methods=["GET"])
def get_database():
    """
    Get the database overview page
    :return:
    """
    handle = DatabaseController.get_database()
    return render_template("database/list.html", entries=handle)
