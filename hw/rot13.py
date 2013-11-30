
import webapp2
import cgi

def escape_html(s):
    return cgi.escape(s, quote = True)

form="""
<form method="post">
Give me some text to ROT13:
<br>
	<textarea rows="4" cols="50" name="text">%(text)s</textarea>
	<br>
    <input type="submit">
</form>
"""

def rot13(text):
    new_text=""
    for letter in text:
        if letter.isalpha():
            if letter>='a' and letter<='m':
                x = chr(ord(letter)+13)
            if letter>='n' and letter<='z':
                x = chr(ord(letter)+13-26)
            if letter>='A' and letter<='M':
                x = chr(ord(letter)+13)
            if letter>='N' and letter<='Z':
                x = chr(ord(letter)+13-26)
        else:
            x = letter
        new_text = new_text + x
    return new_text

class MainPage(webapp2.RequestHandler):
    def write_form(self, text=""):
        text = rot13(text)
        self.response.out.write(form % {"text": escape_html(text)})

    def get(self):
        self.write_form()

    def post(self):
        text = self.request.get('text')
        self.write_form(text)

app = webapp2.WSGIApplication([('/', MainPage)], debug=True)

