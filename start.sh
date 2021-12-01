#!/usr/bin/env bash
export TERM=linux
export TERMINFO=/bin/bash
gunicorn main:flask -b 0.0.0.0:7300 -w 4 -t 1200