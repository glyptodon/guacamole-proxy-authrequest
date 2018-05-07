guacamole-proxy-authrequest
===========================

guacamole-proxy-authrequest is an extension for [Apache
Guacamole](http://guacamole.apache.org) which allows proxied web applications
to be made available to authenticated users of Guacamole strictly for the
duration of their session.

There are no configuration options for the extension. Once the extension is
installed, a cookie will be set for all authenticated users which can be used
to authenticate other requests as long as those requests are within the path
used by the cookie. Depending on how your reverse proxy is set up, this will
likely mean that the other web applications will need to be served beneath the
same domain and path as Guacamole itself.

How it works
------------

This extension depends on the use of the [`ngx_http_auth_request`](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) module. This module allows
HTTP requests to particular locations to be allowed/denied based on the
response another HTTP request made by the Nginx server.

This extension exposes a REST endpoint, `.../api/ext/proxy-authrequest` which
can be used to test for the existence of a cookie set by the extension in
response to successful authentication within Guacamole. The cookie is set in
such a way that it will be valid only while the user is logged into Guacamole.

HTTP requests to `.../api/ext/proxy-authrequest` will return HTTP 200 and the
JSON value `true` for authenticated users, and will return HTTP 403 and the
JSON value `false` for users that are not authenticated.

Configuring Nginx
-----------------

To force requests to a particular location to be allowed only for authenticated
users of Guacamole, include an `auth_request` directive within the
applicable `location` block which points to the endpoint mentioned above:

```
location /guacamole/someOtherWebApplication {
    auth_request /guacamole/api/ext/proxy-authrequest;
    proxy_pass http://myapp:8080/;
    ...
```

As long as the path for the `location` is beneath the path used by your
deployment of Guacamole, the request sent to the endpoint referenced by the
`auth_request` directive will contain the cookie set by this extension, thus
tying the success of the overall request to whether the user is authenticated
within Guacamole.

