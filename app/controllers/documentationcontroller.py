"""
Documentation, yeah!
"""

from flask import render_template
from app import flask


@flask.route("/docs")
def documentation_root():
    """
    Get introduction page
    :return:
    """
    return render_template('docs/index.html', sub="Index")


@flask.route("/docs/getting-started")
def documentation_getting_started():
    """
    Getting started page
    :return:
    """
    return render_template('docs/getting_started.html', sub="Getting started")


@flask.route("/docs/dynamic-analysis")
def documentation_dynamic():
    """
    Get dynamic analyser page
    :return:
    """
    return render_template('docs/dynamic.html', sub="Dynamic Analysis")


@flask.route("/docs/troubleshooting")
def documentation_troubleshooting():
    """
    Get troubleshooting page
    :return:
    """
    return render_template('docs/troubleshooting.html', sub="Troubleshooting")
