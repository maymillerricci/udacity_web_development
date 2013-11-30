#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import webapp2
import cgi

def escape_html(s):
    return cgi.escape(s, quote = True)

form="""
<form method="post">
<label>
    Username
    <input type="text" name="username" value="%(username)s">
</label>
<div style="color: red">%(error1)s</div>
<br>
<label>
    Password
    <input type="password" name="password">
</label>
<div style="color: red">%(error2)s</div>
<br>
<label>
    Verify Password
    <input type="password" name="verify">
</label>
<div style="color: red">%(error3)s</div>
<br>
<label>
    Email (optional)
    <input type="text" name="email" value="%(email)s">
</label>
<div style="color: red">%(error4)s</div>
<br>
<input type="submit">
</form>
"""

import re
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PASSWORD_RE.match(password)

def valid_verify(password, verify):
    if password == verify:
        return verify

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
        return not email or EMAIL_RE.match(email)


class MainPage(webapp2.RequestHandler):
    def write_form(self, username="", email="", error1="", error2="", error3="", error4=""):
        self.response.out.write(form % {"username": escape_html(username),
                                        "email": escape_html(email),
                                        "error1": error1,
                                        "error2": error2,
                                        "error3": error3,
                                        "error4": error4})

    def get(self):
        self.write_form()

    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')

        username = valid_username(user_username)
        password = valid_password(user_password)
        verify = valid_verify(user_password, user_verify)
        email = valid_email(user_email)

        if not(username) or not(password) or not(verify) or not(email):
            error1=""
            error2=""
            error3=""
            error4=""
            if not(username):
                error1 = "That's not a valid username."
            if not(password):
                error2 = "That's not a valid password."
            if not(verify):
                error3 = "Your passwords do not match."
            if not(email):
                error4 = "That's not a valid email."
            self.write_form(user_username, user_email, error1, error2, error3, error4)
        else:
            self.redirect("/thanks?username=" + user_username)


class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        username = self.request.get('username')
        self.response.out.write("Welcome, " + username + "!")


app = webapp2.WSGIApplication([('/', MainPage),
                                ('/thanks', ThanksHandler)], 
                                debug=True)



