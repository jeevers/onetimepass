onetimepass
============

Proof of concept two factor authentication webapp using Tornado, pyotp, and peewee.

Setup
-----
- Install packages in requirements.txt
- Initialize DB by running db.init_db([db.User], db.db)
- Create users using db.create_user(username, password, email)
- Run onetimepass.py

URLs of interest
----------------
- http://server_ip:8800/ -- simple "hello <username>" page (redirects to /login if not authenticated)
- http://server_ip:8800/login -- Login page
- http://server_ip:8800/logout -- Logout and redirect to /login
- http://server_ip:8800/qr -- QR code for time-based OTP (TOTP) code that can be used in google authenticator
- http://server_ip:8800/totp/<username> -- Outputs TOTP code for specified user
- http://server_ip:8800/hotp/<username> -- Outputs counter based OTP (HOTP) for specified user

TODO
----
- Admin page (for user creation/deletion)
- add command-line functionality to db.py to allow DB intialization and admin user creation
- Allow accounts to not use OTP (for initial login and setup)
- Implement HTTPS. Unencrypted passwords over the wore is not cool, bro.
- Create Tests 
