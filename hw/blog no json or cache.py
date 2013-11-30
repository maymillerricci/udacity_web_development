#set-up
import os
import webapp2
import jinja2
import cgi
import re
import random
import string
import hashlib
import hmac

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader('templates'), 
    autoescape = True)

def escape_html(s):
    return cgi.escape(s, quote = True)

# info for generic handler
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))
    
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        if cookie_val and check_secure_val(cookie_val):
            return cookie_val

#user database
def user_key(name = 'default'):
    return db.Key.from_path('users', name)

class User(db.Model):
    username = db.StringProperty(required = True)
    password_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)

#for username and password validation on signup page
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

#for username and password validation
secret = "secretpasscode"

def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(username, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username + pw + salt).hexdigest()
    return '%s|%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split('|')[0]
    return h == make_pw_hash(name, password, salt)

#sign-up page
class Signup(Handler):  
    def write_form(self, username="", email="", error1="", error2="", error3="", error4=""):
        self.render("blog_signup.html", username=username, email=email, error1=error1, error2=error2, error3=error3, error4=error4)

    def get(self):
        self.write_form()

    def post(self):
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')

        u = User.all().filter('username =', user_username).get()
        if u:
            self.render('blog_signup.html', error1 = 'That username already exists.')
        else:
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
                self.write_form(username=user_username, email=user_email, error1=error1, error2=error2, error3=error3, error4=error4)
            else:
                pw_hash = make_pw_hash(user_username, user_password)
                u = User(username = user_username, password_hash = pw_hash, email=user_email)
                u.put()
                self.set_secure_cookie('user_name', str(user_username))
                self.redirect("/blog/welcome")

#welcome page once registered
class Welcome(Handler):
    def get(self):
        user_hash = self.read_secure_cookie('user_name')
        if user_hash:
            user_name = user_hash.split('|')[0]
            self.response.out.write("Welcome %s!" % user_name)
        else:
            self.redirect('/blog/signup')

#login
class Login(Handler):
    def get(self):
        self.render('blog_login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        
        u = User.all().filter('username =', username).get()
        if u and valid_pw(username, password, u.password_hash):
            self.set_secure_cookie('user_name', str(username))
            self.redirect('/blog/welcome')
        else:
            self.render('blog_login.html', error2 = 'Invalid login')

#logout
class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_name=; Path=/')
        self.redirect('/blog/signup')

#create blog entry database
class Blog(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

#main blog page listing blog entries
class Main(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC limit 10")
        self.render("blog_front.html", posts=posts)

#new post page
class Post(Handler):
    def render_newpost(self, subject="", content="", error=""):
        self.render("blog_newpost.html", subject=subject, content=content, error=error)

    def get(self):
        self.render_newpost()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            b = Blog(parent = blog_key(), subject = subject, content = content)
            b.put()
            self.redirect("/blog/%s" % str(b.key().id()))
        else:
            error = "Subject and content, please!"
            self.render_newpost(subject=subject, content=content, error=error)

#permalink for blog entry just submitted (thanks)
class Thanks(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)
        self.render("blog_permalink.html", post=post)

#navigation
app = webapp2.WSGIApplication([('/blog/?', Main),
                                ('/blog/signup', Signup),
                                ('/blog/welcome', Welcome),
                                ('/blog/login', Login),
                                ('/blog/logout', Logout),
                                ('/blog/newpost', Post), 
                                 ('/blog/([0-9]+)', Thanks)], 
                                debug=True)



