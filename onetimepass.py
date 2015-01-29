"""
Proof of concept two-factor authentication using a one time password
as the second factor. Hashed passwords and the OTP secret are stored
in a SQLite database.
"""

import tornado.httpserver
import tornado.ioloop
import tornado.web
import tornado.gen
import os
import signal

import qrcode
import StringIO
import pyotp

import db
import auth


class BaseHandler(tornado.web.RequestHandler):
    """
    Overidden get_current_user method needed to handle
    the authenication decorators.
    """
    def get_current_user(self):
        username = self.get_secure_cookie("user")
        #userinfo = db.get_user(username)
        #return userinfo
        if not username:
            return None
        return username


class LoginHandler(BaseHandler):
    """
    Takes input from form and logs the user in if everything
    checks out. Will accept both time and counter based qr codes.
    Stores username in a secure cookie.
    """
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.get_argument("name")
        password = self.get_argument("password")
        otp = self.get_argument("otp")
        otp_type = self.get_argument("otptype")
        try:
            userinfo = db.get_user(username)
            if otp_type == "hotp":
                otp_obj = pyotp.HOTP(userinfo.otp_secret)
                otp_verify = otp_obj.verify(otp, userinfo.hotp_counter)
                userinfo.hotp_counter = userinfo.hotp_counter + 1
                userinfo.save()
            elif otp_type == "totp":
                otp_obj = pyotp.TOTP(userinfo.otp_secret)
                otp_verify = otp_obj.verify(otp)

            if (auth.verify_hash(password, userinfo.passwdhash) and
                otp_verify):
                self.set_secure_cookie("user", username)
                self.redirect("/")
            else:
                self.redirect("/login")
        except db.User.DoesNotExist:
            self.redirect("/login")

class LogoutHandler(BaseHandler):
    """
    'Logs out' user by clearing cookie. Does not really
    work in Firefox
    """
    def get(self):
        self.clear_cookie("user")
        self.redirect("/")


class MainHandler(BaseHandler):
    """
    Returns a "hello, <username>" string to show that the authentication
    worked
    """
    @tornado.web.authenticated
    def get(self):
        name = tornado.escape.xhtml_escape(self.current_user)
        self.write("hello, " + name)


class QRHandler(BaseHandler):
    """
    Return a QR code containing the provisioning URL(URI?)
    that can be imported into the google authenticator app
    """
    @tornado.web.authenticated
    def get(self):

        current_user = db.get_user(self.get_current_user())

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_Q,
            box_size=20,
            border=4
        )

        totp = pyotp.TOTP(current_user.otp_secret)
        goog_authenticator_url = totp.provisioning_uri(current_user.email)

        qr.add_data(goog_authenticator_url)
        qr.make(fit=True)

        img = qr.make_image()

        self.set_header("Content-type", "image/png")

        img_buff = StringIO.StringIO()
        img.save(img_buff)
        img_buff.seek(0)
        self.write(img_buff.read())
        self.finish()

class HOTPCodeHandler(BaseHandler):
    """
    Returns counter based OTP for a given user.
    Don't use this in prod. Send an email or text or something.
    """
    def get(self, username):
        try:
            userinfo = db.get_user(username)
            hotp = pyotp.HOTP(userinfo.otp_secret)
            otp_key = hotp.at(userinfo.hotp_counter)
            self.write(str(otp_key))
        except db.User.DoesNotExist:
            self.send_error(404)

class TOTPCodeHandler(BaseHandler):
    """
    Returns time based OTP for a given user.
    Don't use this in prod. Use the google authenticator app.
    """
    def get(self, username):
        try:
            userinfo = db.get_user(username)
            totp = pyotp.TOTP(userinfo.otp_secret)
            otp_key = totp.now()
            self.write(str(otp_key))
        except db.User.DoesNotExist:
            self.send_error(404)

routes = [
    (r'/qr', QRHandler),
    (r'/login', LoginHandler),
    (r'/logout', LoginHandler),
    (r'/', MainHandler),
    (r'/hotp/([a-zA-Z0-9]*)', HOTPCodeHandler),
    (r'/totp/([a-zA-Z0-9]*)', TOTPCodeHandler),
]

settings = dict(
    static_path=os.path.join(os.path.dirname(__file__), "static"),
    template_path=os.path.join(os.path.dirname(__file__), "templates"),
    cookie_secret="uybuoybou2bybu2u3b4uyb5ouybljkn",
    login_url="/login"
)

application = tornado.web.Application(routes, **settings)

if __name__ == '__main__':
    http_server = tornado.httpserver.HTTPServer(application)
    port_listen = 8800
    http_server.listen(port_listen)
    loop = tornado.ioloop.IOLoop.instance()

    def sigint_handler(signum, frame):
        print('signal handler called with %s, frame %s' % (signum, frame))
        #periodic_cbk.stop()
        loop.stop()
    signal.signal(signal.SIGINT, sigint_handler)
    signal.signal(signal.SIGHUP, sigint_handler)
    signal.signal(signal.SIGTERM, sigint_handler)
    #periodic_cbk = tornado.ioloop.PeriodicCallback(ip_poll, 
    #                                               poll_interval*60*1000,
    #                                               loop)
    #periodic_cbk.start()
    loop.start()
 
# vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab:
