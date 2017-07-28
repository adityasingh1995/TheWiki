import os
import re
import hashlib
import jinja2
import hmac

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),autoescape = True)

secret = 'sexy'

def fix_name(name):
    if name != '/':
        return name[1:]
    else:
        return name
def unfix_name(name):
    if name == '/':
        return ""
    else:
        return name

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
MAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
PASS_RE = re.compile(r"^.{3,20}$")

def valid_username(username):
    return USER_RE.match(username) and username

def valid_password(password):
	return PASS_RE.match(password) and password

def valid_email(email):
	return not email or MAIL_RE.match(email)

