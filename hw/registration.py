import webapp2
import cgi
import os
import jinja2

from google.appengine.ext import db

def user_key(name = 'default'):
    return db.Key.from_path('users', name)

def escape_html(s):
    return cgi.escape(s, quote = True)

class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

form="""
<form method="post">
<h2>Signup</h2>
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

import random
import string

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

import hashlib

def make_pw_hash(username, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username + pw + salt).hexdigest()
    return '%s|%s' % (username, h)


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
            u = User(parent = user_key(), username = user_username, password = user_password)
            u.put()
            h = make_pw_hash(str(user_username), str(user_password))
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.headers.add_header('Set-Cookie', 'hash=%s; Path=/' % h)
            self.redirect("/blog/welcome")


class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        hash = self.request.cookies.get('hash')
        username = hash.split('|')[0]
        self.response.out.write("Welcome, " + username + "!")

app = webapp2.WSGIApplication([('/blog/signup', MainPage),
                                ('/blog/welcome', ThanksHandler)], 
                                debug=True)



