import os
import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader('templates'), 
    autoescape = True)

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Blog(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

class MainPage(Handler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Blog ORDER BY created DESC limit 10")
        self.render("blog_front.html", posts=posts)

class PostHandler(Handler):
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

class ThanksHandler(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Blog', int(post_id), parent=blog_key())
        post = db.get(key)
        self.render("blog_permalink.html", post=post)

app = webapp2.WSGIApplication([('/blog/?', MainPage),
                                ('/blog/newpost', PostHandler), 
                                 ('/blog/([0-9]+)', ThanksHandler)], 
                                debug=True)



