"""
Could have added this to some other controller
Didn't.. not sure why
"""
import json

from flask import render_template
from app import flask


from app.models.security import MobileBinaryResult


@flask.route("/binaries/<app_id>", methods=["GET"])
def get_apk_binaries(app_id):
    """
    Get binary result information
    Basic pwntool output
    :param app_id:
    :return:
    """
    output_list = []

    get_bins = MobileBinaryResult.query.filter(
        MobileBinaryResult.application_id == app_id
    ).all()

    for binary in get_bins:
        data = {
            "name": binary.binary.split(f"{app_id}/")[1],
            "data": json.loads(binary.data)
        }
        output_list.append(data)

    return render_template("binaries.html", binaries=output_list, app_id=app_id)
