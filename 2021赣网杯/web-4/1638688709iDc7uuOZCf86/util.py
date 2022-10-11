#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import re


def htmlencode(s):
    res = ''
    for char in s:
        res += "&#%d;" % ord(char)
    return res


def data_wash(s: str):
    pattern = re.compile(r'''<script>|<\/script>|on|func|javascript|flag|127\.|var|\'|\"|fetch|eval|\$|ajax|token''', re.I)
    finds = re.findall(pattern, s)
    for word in finds:
        s = s.replace(word, htmlencode(word))
    return s

