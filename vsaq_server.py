# Copyright 2016 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Runs a test server for VSAQ."""

from flask import Flask, redirect, url_for, request
from flask_bcrypt import Bcrypt

from datetime import datetime, timedelta
import jwt
import json
import sqlite3 as db
import random
import string

import BaseHTTPServer
import cgi
import fnmatch
import os
import os.path
import re
import SimpleHTTPServer
import sys


JWT_SECRET = 'secret'
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_MINUTES = 20

BASE_DIR = "/Users/sanjeet.roy/Desktop/webserver-1.2"
db_path = os.path.join(BASE_DIR, "testDB.db")

conn = db.connect(db_path)
curs = conn.cursor()


app = Flask(__name__)
bcrypt =  Bcrypt(app)

PORT = 9000
if len(sys.argv) > 1:
  PORT = int(sys.argv[1])

server_address = ("127.0.0.1", PORT)

#./ do.sh testserver generates the file
DEPS_FILE = "build/deps-runfiles.js"
ALL_JSTESTS_FILE = "build/all_tests.js"


class TestServerRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
  """Request handler for VSAQ test server."""

  DIRECTORY_MAP = {
      "/": "build/",
      "/vsaq/": "vsaq/",
      "/vsaq/static/questionnaire/": "vsaq/static/questionnaire/",
      "/javascript/closure/": "third_party/closure-library/closure/goog/",
      "/javascript/vsaq/": "vsaq/",
      "/third_party/closure/":
          "third_party/closure-library/third_party/closure/",
      "/third_party/closure-templates-compiler/":
          "third_party/closure-templates-compiler/",
      "/build/templates/vsaq/static/questionnaire/":
          "build/templates/vsaq/static/questionnaire/",

  }

  def get_test_files(self):
    test_files = []
    for root, _, files in os.walk("vsaq/"):
      for f in fnmatch.filter(files, "*test_dom.html"):
        test_files.append(os.path.join(root, f))
    return test_files

  def generate_all_tests_file(self):
    if os.path.exists(ALL_JSTESTS_FILE):
      return
    with open(ALL_JSTESTS_FILE, "wb") as f:
      f.write("var _allTests=")
      f.write(repr(self.get_test_files()))
      f.write(";")

  def show_tests(self):
    """Lists only vsaq/**/_test.html files."""
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.end_headers()
    test_files = self.get_test_files()

    self.wfile.write("<h2>VSAQ test server</h2>")
    self.wfile.write("<h3>Test suite</h3>")
    self.wfile.write("<a href=\"%s\">%s</a>\n" % ("/all_tests.html",
                                                  "all_tests.html"))
    self.wfile.write("<h3>Individual tests</h3>")
    self.wfile.write("<ul>")
    for f in test_files:
      self.wfile.write("<li><a href=\"/%s\">%s</a>\n" % (f, cgi.escape(f)))
    self.wfile.write("</ul>")
    return


  def goto_home(self):
    f = open("build/home.html", "r")
    self.wfile.write(f.read())
    return

  def logout_jti(self,jti):
    query = "update jtiTb set status= 'logged-out' where jti=?"
    curs.execute(query,(jti,))
    return

  def insert_jti(self,jti,status):
    curs.execute("insert into jtiTb values (?,?)", (jti,status))
    conn.commit()

    return

  def insert_indb(self,inputArgs):
    name = inputArgs['name'][0]
    passHash = bcrypt.generate_password_hash(
                      inputArgs['password'][0], app.config.get('BCRYPT_LOG_ROUNDS')
                  ).decode()
    curs.execute("insert into users values (?,?)", (name,passHash))
    conn.commit()

    print "Successfully Inserted"
    self.goto_loginSuccess()
    return

  def get_jti(self):
    system_random = random.SystemRandom()
    jti_length = system_random.randint(16, 128)
    ascii_alphabet = string.ascii_letters + string.digits
    ascii_len = len(ascii_alphabet)
    jti = ''.join(ascii_alphabet[int(system_random.random() * ascii_len)] for _ in range(jti_length))
    return jti

  def check_user(self,inputArgs):
    name = inputArgs['username'][0]
    input_pass = inputArgs['password'][0]

    if name != '' and input_pass != '':
      query = "select pass from users where username=?";
      curs.execute(query,(name,))
      result = curs.fetchone()

      if result != None:
        retrieve_pass = result[0]

        if bcrypt.check_password_hash(retrieve_pass,input_pass):

          jti = self.get_jti()
          self.insert_jti(jti,"logged-in")

          payload = {
            'user_id': name,
            'exp': datetime.utcnow() + timedelta(minutes=JWT_EXP_DELTA_MINUTES),
            'jti': jti
          }

          jwt_token = jwt.encode(payload, JWT_SECRET, JWT_ALGORITHM)
          return jwt_token,'authentic'


    return '','un-authentic'

  def goto_loginSuccess(self):
      f = open("build/login-success.html", "r")
      self.wfile.write(f.read())
      return

  def goto_loginError(self):
    f = open("build/login-error.html", "r")
    self.wfile.write(f.read())
    return

  def goto_login(self):
    self.send_response(200)  # OK
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    f = open("build/index.html", "r")
    self.wfile.write(f.read())
    return

  def get_cookie_handle(self,cookie_bw):
    cookies = cookie_bw.split(";")
    handler = {}
    for cookie in cookies:
      cookie = cookie.split('=')
      handler[cookie[0]] = cookie[1]

    return handler

  def get_jti_status(self,jti):
    query = "select status from jtiTb where jti=?"
    curs.execute(query,(jti,))
    result = curs.fetchone()

    if result != None:
      return result[0]
    else:
      return 'logged-out'

  def useris_loggedin(self,cookie):
    if cookie == None:
      return False
    else:
      cookie_handle = self.get_cookie_handle(cookie)
      try:
        access_token = cookie_handle['access_token']
        jwt_token = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
        login_status = get_jti_status(jwt_token['jti'])

        if login_status == 'logged-in':
            return true
      except:
        return False

    return False


  def logout(self,cookie):
    access_token = "access_token=deleted; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"

    cookie_handle = self.get_cookie_handle(cookie)
    try:
      access_token = cookie_handle['access_token']
      jwt_token = jwt.decode(access_token, JWT_SECRET, JWT_ALGORITHM)
      logout_jti(jwt_token['jti'])
    except:
      print "Some Error in loggin-out"

    self.send_response(301)  # OK
    self.send_header('Content-type', 'text/html')
    self.send_header('Set-Cookie', access_token)
    self.send_header("Location", "/index.html")
    self.end_headers()

  def do_GET(self):
    print self.path
    cookie = self.headers.get('Cookie')
    print "cookie = ",cookie

    print "status"
    print self.useris_loggedin(cookie)

    if self.path == "/tests.html" or self.path == "/tests.html/":
      self.show_tests()
    else:
      SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)
      #self.goto_login()

    '''
    elif cookie != None and self.useris_loggedin(cookie):
      if self.path == "/logout":
        self.logout(cookie)
      else:
        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)
    '''

  def do_POST(self):
    ctype, pdict = cgi.parse_header(self.headers['content-type'])
    if ctype == 'multipart/form-data':
      postvars = cgi.parse_multipart(self.rfile, pdict)
    elif ctype == 'application/x-www-form-urlencoded':
      length = int(self.headers['content-length'])
      postvars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)
    else:
      postvars = {}

    if len(postvars) == 2:
      print "sign-in"
      token,result = self.check_user(postvars)
      access_token = "access_token=" + token
      url_path = ''

      if result=='authentic':
        url_path = "/home.html"
      else:
        url_path = "/login-error.html"

      self.send_response(301)  # OK
      self.send_header('Content-type', 'text/html')
      self.send_header('Set-Cookie', access_token)
      self.send_header("Location", url_path)
      self.end_headers()

    elif len(postvars) == 3:
      print "sign-UP"
      self.insert_indb(postvars)


    '''
    if postvars['username'][0] == "admin":
      print postvars['password'][0]
      password = bcrypt.generate_password_hash(
                  postvars['password'][0], app.config.get('BCRYPT_LOG_ROUNDS')
              ).decode()

      self.insert_indb(postvars['username'][0],password)
      print password
      self.goto_home()
    else:
      self.goto_loginError()
    '''

  def translate_path(self, path):
    """Serves files from different directories."""
    # Remove all parameters from filenames.
    path = re.sub(r"\?.*$", "", path)

    if path.endswith("deps-runfiles.js"):
      return DEPS_FILE
    if path == "/" + ALL_JSTESTS_FILE:
      self.generate_all_tests_file()
      return ALL_JSTESTS_FILE
    for prefix, dest_dir in TestServerRequestHandler.DIRECTORY_MAP.items():
      print "checking: " + dest_dir + path[len(prefix):]
      if path.startswith(prefix) and os.path.isfile(
          dest_dir + path[len(prefix):]):
        return dest_dir + path[len(prefix):]
    return "build/index.html"


httpd = BaseHTTPServer.HTTPServer(server_address, TestServerRequestHandler)
print "Starting the VSAQ server at http://%s:%d" % server_address
httpd.serve_forever()
