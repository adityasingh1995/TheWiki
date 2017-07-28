from google.appengine.ext import db
from string import letters
import random
import hashlib

##### page stuff
def page_key(name):
    parent_name = name+'_parent'
    return db.Key.from_path('pageparent', parent_name)

class Page(db.Model):
    name = db.StringProperty(required = True)
    content = db.TextProperty()
    lastmod = db.DateTimeProperty(auto_now_add = True)

    @classmethod
    def by_id(cls, name, pid):
        p = Page.get_by_id(pid, parent = page_key(name))
        return p

    @classmethod
    def list_all_name(cls, name):
        new = list()
        p = cls.all().ancestor(page_key(name)).order('-lastmod')
        for a in p.run():
            new.append(a)
        return new

    @classmethod
    def by_name(cls, name):
        p = cls.all().ancestor(page_key(name)).order('-lastmod').get()
        return p

    @classmethod
    def newpage(cls, name, content):
        p = cls(parent = page_key(name), name = name, content=content)
        return p


##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

