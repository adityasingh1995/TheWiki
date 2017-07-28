import webapp2
import os
import re
from myorm import *
from myutils import *
import logging
import time

class WikiHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))



class Signup(WikiHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            u = User.by_name(self.username)
            if u:
                msg = 'That user already exists.'
                self.render('signup-form.html', error_username = msg)
            else:
                u = User.register(self.username, self.password, self.email)
                u.put()
                self.login(u)
                self.redirect('/')

class Login(WikiHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(WikiHandler):
    def get(self):
        self.logout()
        self.redirect('/')

class EditPage(WikiHandler):
    def get(self, name):
        if not self.user:
            logging.error('not logged in, redirecting')
            self.redirect('/login')
        else:
            name = fix_name(name)
            page_id = self.request.get("page_id")
            if page_id:
                p = Page.by_id(name, int(page_id))
            else:
                p = Page.by_name(name)
            if p:
                content = p.content
            else:
                content = ""
            self.render('editor.html', name=name, content=content, user = self.user)

    def post(self, name):
        name = fix_name(name)
        if not self.user:
            self.redirect('/login')
        content = self.request.get("content")
        if not name:
            logging.error('not name, redirecting')
            self.redirect('/')
        else:
            if not content:
                self.render('editor.html', name= name, user = self.user, error = "please add content")
            else:
                p = Page.newpage(name, content)
                p.put()
                name = unfix_name(name)
                time.sleep(0.5)
                self.redirect('/%s' % name)

#class MainPage(WikiHandler):
#    def get(self):
#        if self.user:
#            self.response.out.write("logged in as %s" % self.user.name)
#        else:
#            self.response.out.write("not logged in")

class WikiPage(WikiHandler):
    def get(self, name):
        page_id = self.request.get("page_id")
        name = fix_name(name)
        if page_id:
            p = Page.by_id(name, int(page_id))
        else:
            p = Page.by_name(name)
        if p:
            self.render("wikipage.html", name = unfix_name(p.name), content = p.content, user = self.user, page_id = page_id)
        else:
            self.redirect("/_edit/%s" % unfix_name(name))

class  HistoryPage(WikiHandler):
    def get(self, name):
        name = fix_name(name)
        plist = Page.list_all_name(name)
        self.render("history.html", name = unfix_name(name), plist = plist, user = self.user)

class Create(WikiHandler):
    def get(self):
        name = self.request.get("new")
        if name:
            self.redirect("/%s" % name.lower())
        else:
            self.redirect("/")



### url handing
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/create', Create),
                               ('/_edit' + PAGE_RE, EditPage),
                               ('/_history' + PAGE_RE, HistoryPage),
                               (PAGE_RE, WikiPage),
                               ],
                              debug=True)

