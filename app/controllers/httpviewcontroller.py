"""
Dashboard for viewing HTTP requests, responses and basic stuff
"""
import json

import kafka
from flask import render_template, redirect, url_for, jsonify
from kafka import TopicPartition
from kafka.errors import KafkaError
from sqlalchemy import and_
from app import flask, db

from app.models.file import (HTTPModel, HTTPFinding, Screenshot)
from config import Config


def get_out_pool(application):
    """
    Get all HTTP request/responses and group them by hostname
    Also includes findings
    :param application:
    :return:
    """
    all_items = HTTPModel.query.filter(
        HTTPModel.application_id == application
    ).all()
    out_pool = {}
    for item in all_items:
        parsed = item.to_obj()
        get_findings = HTTPFinding.query.filter(
            HTTPFinding.remote_id == item.id
        )
        for finding in get_findings.all():
            parsed["findings"].append(finding.to_obj())
        if item.host in out_pool:
            out_pool[item.host].append(parsed)
        else:
            out_pool[item.host] = [parsed]
    return out_pool


@flask.route("/dynamic/http/<application>", methods=["GET"])
def get_http_requests(application):
    """
    Load the Request / Response overview dashboard
    :param application:
    :return:
    """
    return render_template(
        "dynamic/httpviewer.html",
        application=application,
        request_pool=get_out_pool(application),
        selected=None
    )


@flask.route("/dynamic/logs/<application>", methods=["GET"])
def get_frida_logs(application):
    """
    Load the frida logs from kafka consumer
    :param application:
    :return:
    """
    try:
        connection = kafka.KafkaConsumer(
            bootstrap_servers=Config.kafka_servers,
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            auto_offset_reset='earliest',
            group_id=None,
            consumer_timeout_ms=1000
        )

        get_all = []
        topic = f'frida-{application}'
        tp = TopicPartition(topic, 0)
        # register to the topic
        connection.assign([tp])

        # obtain the last offset value
        connection.seek_to_beginning([tp])
        last_entry = connection.position(tp)

        connection.seek_to_beginning(tp)

        for message in connection:
            connection.commit()
            get_all.append(message.value)
            if message.offset == last_entry - 1:
                break
        connection.close()
        get_all.reverse()
    except KafkaError:
        get_all = "error"

    return render_template(
        "dynamic/frida_logs.html",
        application=application,
        frida_logs=get_all
    )


@flask.route("/dynamic/screenshots/<application>", methods=["GET"])
def get_application_screenshots(application):
    """
    Get stored screenshots for a specific application
    :param application:
    :return:
    """
    get_all = Screenshot.query.filter(
        Screenshot.application_id == application
    ).all()

    out_obj = [get_obj.to_obj() for get_obj in get_all]

    return render_template(
        "dynamic/screenshots.html",
        application=application,
        images=out_obj
    )


@flask.route("/dynamic/api/logs/<screenshot_id>", methods=["GET"])
def remove_screenshot(screenshot_id):
    """
    Remove screenshot with id
    """
    Screenshot.query.filter(
        Screenshot.id == screenshot_id
    ).delete()
    db.session.commit()
    return jsonify({"result": True})


@flask.route("/dynamic/api/logs/<application>", methods=["GET"])
def get_frida_logs_api(application):
    """
    Load the frida logs from kafka consumer
    :param application:
    :return:
    """
    connection = kafka.KafkaConsumer(
        bootstrap_servers=Config.kafka_servers,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset='earliest',
        group_id=None,
        consumer_timeout_ms=1000
    )

    get_all = []
    topic = f'frida-{application}'
    partition = TopicPartition(topic, 0)
    # register to the topic
    connection.assign([partition])

    # obtain the last offset value
    connection.seek_to_end(partition)
    last_entry = connection.position(partition)

    connection.seek_to_beginning(partition)

    for message in connection:
        get_all.append(message.value)
        if message.offset == last_entry - 1:
            break

    return jsonify(get_all)


@flask.route("/dynamic/http/<application>/<host>", methods=["GET"])
def delete_http_requests(host, application):
    """
    Deletes all request / response pairs from a host
    :param host:
    :param application:
    :return:
    """
    sub_stmt = db.session.query(
        HTTPModel.id
    ).filter(
        and_(
            HTTPModel.host == host,
            HTTPModel.application_id == application
        )
    )
    db.session.query(
        HTTPFinding
    ).filter(HTTPFinding.remote_id.in_(sub_stmt)).delete(synchronize_session=False)

    HTTPModel.query.filter(
        and_(
            HTTPModel.host == host,
            HTTPModel.application_id == application
        )
    ).delete()
    db.session.commit()
    return redirect(url_for('get_http_requests', application=application))


@flask.route("/dynamic/http_request/<request_id>", methods=["GET"])
def get_http_request_id(request_id):
    """
    Get a single request and return it as the "selected" argument
    :param request_id:
    :return:
    """
    selected = HTTPModel.query.filter(
        HTTPModel.id == request_id
    )
    if selected.count() == 0:
        return "No bueno"
    selected = selected.first()
    obj = selected.to_obj()
    get_findings = HTTPFinding.query.filter(
        HTTPFinding.remote_id == selected.id
    )
    for finding in get_findings.all():
        finding_obj = finding.to_obj()
        if finding_obj not in obj["findings"]:
            obj["findings"].append(finding_obj)
    application = selected.application_id
    return render_template(
        "dynamic/httpviewer.html",
        application=application,
        request_pool=get_out_pool(selected.application_id),
        selected=obj
    )
