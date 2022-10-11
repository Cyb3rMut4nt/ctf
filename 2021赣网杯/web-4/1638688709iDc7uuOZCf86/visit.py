#!/usr/bin/env python
# -*- coding: utf-8 -*-

from selenium import webdriver
from queue import Queue


class Visit:
    def __init__(self):
        self.url_queue = Queue(maxsize=3)

    def getsize(self):
        return self.url_queue.qsize()

    def addNote(self, noteid):
        if not self.url_queue.full():
            self.url_queue.put("http://127.0.0.1/note?note=" + noteid)
            while self.url_queue.qsize():
                self.chromeVisit(self.url_queue.get())
            return True
        return False

    def chromeVisit(self, url):
        print("chrome visit", url)
        driver = webdriver.Chrome()
        driver.set_page_load_timeout(20)
        try:
            driver.get(url)
        except Exception as ee:
            print(ee)
        finally:
            driver.close()
            driver.quit()


visitObj = Visit()
