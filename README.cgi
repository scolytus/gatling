Gatling now has primitive CGI support.

To use it, touch ".proxy" in the root of the virtual host, for example

  $ touch default/.proxy

and then start gatling with -C and a regex by which to detect CGIs:

  # gatling -C '\.cgi'

