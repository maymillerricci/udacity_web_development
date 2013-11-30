import os
import webapp2
import jinja2
import urllib2
from xml.dom import minidom
import logging

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader('templates'), 
    autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

def gmaps_img(points):
    GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false"
    for p in points:
        GMAPS_URL = GMAPS_URL + "&markers=" + str(p.lat) + "," + str(p.lon)
    return GMAPS_URL

IP_URL = "http://api.hostip.info/?ip="
def get_coords(ip):
    ip = "4.2.2.2"
    url = IP_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url).read()
    except URLError:
        return

    if content:
        #parse the xml and find the coordinates
         d = minidom.parseString(content)
         coords = d.getElementsByTagName("gml:coordinates")
         if coords and coords[0].childNodes[0].nodeValue:
             lon, lat = coords[0].childNodes[0].nodeValue.split(',')
             return db.GeoPt(lat, lon)

class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty()

def top_arts(update = False):
    key = 'top'
    arts = memcache.get(key)
    if arts is None or update:
        logging.error("DB QUERY")
        arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC LIMIT 10")
        #prevent the running of multiple queries
        arts = list(arts)
        memcache.set(key, arts)
    return arts

class MainPage(Handler):
    def render_front(self, title="", art="", error=""):    
        arts = top_arts()
        
        #find which arts have coords
        points = []
        for a in arts:
            if a.coords:
                points.append(a.coords)
        #self.write(repr(points))
        
        #if we have any arts coords, make an image url
        img_url = None
        if points: 
            img_url=gmaps_img(points)
             
        #display the image url

        self.render("ascii_front.html", title=title, art=art, error=error, arts=arts, img_url=img_url)

    def get(self):
        self.render_front()

    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")

        if title and art:
            a = Art(title = title, art = art)
            #lookup user's coordinates from IP
            coords = get_coords(self.request.remote_addr)
            #if coordinates, add them to Art
            if coords:
                a.coords = coords
            a.put()
            top_arts(True)
            self.redirect("/")
        else:
            error = "we need both a title and some artwork!"
            self.render_front(title, art, error)

app = webapp2.WSGIApplication([('/', MainPage)], 
                                debug=True)



