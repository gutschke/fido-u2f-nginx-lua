# Example code for FIDO U2F authentication with the Lua module in nginx

Overview
========

A LUA implementation of the server-side portion of the FIDO U2F protocol.
This code can be used in the "nginx" web server.


Installation
============

Apart from making sure that you have a copy of "nginx" and
"memcached", you must copy the contents of "u2f-nginx.conf" into the
configuration file for your web site, and you must copy "u2f.lua" to a
location where your webserver looks for Lua files. Finally, the
"index.html" and "u2f-api.js" must be copied to a location where the
webserver looks for HTML content.

Open the "index.html" file from your web browser; you can then
register a FIDO U2F token with the server and use it to authenticate
when subsequently logging in.


Limitations
===========

At the time of writing, only Google Chrome version 41 and above has
built-in support for FIDO U2F tokens. But other browser manufacturers
are reportedly working on adding support.

For demonstration purposes, this demo stores all state in a "memcached"
instance that must be running on the same machine. For production use,
that is almost certainly the wrong approach. Most importantly, no
production server should ever store unencrypted passwords.


Licensing
=========

Feel free to copy and paste any and all parts of this code into whatever
code you already use to authenticate users and to manage their active
sessions.

Please note that "u2f-api.js" is copyrighted by and licensed from
Google Inc. It is included here for your convenience, but for details
on licensing, refer to the header in that particular file.

All other files are copyrighted by Markus Gutschke, and they are
intended to be example code that can freely be incorporated in other
projects.
