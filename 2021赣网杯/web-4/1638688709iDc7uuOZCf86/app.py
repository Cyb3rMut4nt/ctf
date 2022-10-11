#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, redirect
from flask_wtf.csrf import CSRFProtect
from util import data_wash
from visit import visitObj
from random import randint
from base64 import b64encode
import string
import sys
import logging
import uuid
import os
import time
import requests

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
FLAG = b64encode(open(os.getenv('flagpath'), 'r').read().encode()).decode()

app = Flask(__name__, static_url_path='')
app.config["SECRET_KEY"] = ''.join([string.ascii_letters[randint(0, 51)] for i in range(50)])
csrf = CSRFProtect(app)
notes = {}
tokens = {}


@app.route("/", methods=['GET'])
def index():
    return render_template('index.html')


@app.route("/note", methods=['GET', 'POST'])
def note():
    if request.method == 'GET':
        if not request.args.get('note') or type(request.args.get('note')) != type('s') or request.args.get(
                'note') not in notes:
            return render_template("note.html", msg="note not found", ok=False, noteid=request.args.get('note'))
        return render_template("note.html", msg=notes[request.args.get('note')], ok=True,
                               noteid=request.args.get('note'))
    # POST
    note_content = request.form.get('note')
    if type(note_content) != type('s'):
        return "not string"
    noteid = str(uuid.uuid4())
    while noteid in notes:
        noteid = str(uuid.uuid4())
    notes[noteid] = data_wash(note_content)
    return redirect('?note=' + noteid)


@app.route("/report", methods=['GET', 'POST'])
def report():
    if request.method == 'POST':
        noteid = request.form.get('note')
        if noteid not in notes:
            return "note not found"
        if visitObj.addNote(noteid):
            return "report success! admin will visit it"
        return "queue is full, please wait a second. you can visit /checkQueue to get the queue size"
    return render_template("report.html")


@app.route("/checkQueue", methods=['GET'])
def checkQueue():
    return {'queue_size': visitObj.getsize()}


@app.route("/flag", methods=['GET', 'POST'])
def flag():
    if request.method == 'GET':
        return render_template("flag.html")
    # POST
    token = request.form.get('token') if request.form.get('token') else request.args.get('token')
    url = request.form.get('url') if request.form.get('url') else request.args.get('url')
    if type(token) != type('s'):
        return "string only"
    if token not in tokens:
        return "token not found"
    if int(time.time()) - tokens[token]['startTime'] >= 60:
        del tokens[token]
        return "token expired"
    userToken = tokens[token]
    # token 已使用，删除
    del tokens[token]
    # 发起访问
    if userToken['isAdmin'] and request.remote_addr == '127.0.0.1':
        path = '/?flag=' + FLAG
        try:
            requests.get(url=url + path, timeout=3)
            return "WELCOME ADMIN! request finished"
        except:
            return "WELCOME ADMIN! Exception!"
    return "not admin, just test"


@app.route("/getToken", methods=['GET', 'POST'])
def getToken():
    # 清理超时Token
    for t in list(tokens):
        if int(time.time()) - tokens[t]['startTime'] >= 60:
            del tokens[t]
    # 生成Token
    token = str(uuid.uuid4())
    while token in tokens:
        token = str(uuid.uuid4())
    if request.remote_addr == '127.0.0.1':
        tokens[token] = {
            'token': token,
            'isAdmin': True,
            'startTime': int(time.time())
        }
    else:
        tokens[token] = {
            'token': token,
            'isAdmin': False,
            'startTime': int(time.time())
        }
    return tokens[token]


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=80, debug=False)
