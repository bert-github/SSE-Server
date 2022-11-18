# SSE-Server

SSE-Server implements an HTTP server that sends Server-Sent Events
(see [section 9.2 of
HTML5](https://html.spec.whatwg.org/multipage/server-sent-events.html)
to connected web clients. (Typically: web pages with JavaScript that
uses the EventSource API.)

SSE-Server supports SSL, but does not implement any form of
authentication. (It is possible to use Apache or another web server as
a reverse proxy and let that server handle the authentication.)

## Receiving events

Web clients connect to this server and then keep the connection open,
waiting for the SSE server to send them messages.

The server provides an arbitrary number of ‘channels’ and clients can
subscribe to one or more of them, or to all of them. They then get the
messages that are sent on the subscribed channels.

## Sending events

Web clients that want to *send* messages to clients on one or more
channels can connect to the server with a query at the end of the
URL. The query contains the message type and the message data.

Messages to send can also be provided through a dedicated port of the
server, separate from the port that web clients connect to. This
‘control port’ accepts simple text lines. (I.e., it does not accept
HTTP.)

And a third way to send messages to web clients is by writing them to
a FIFO file on the machine the server is running on. This FIFO accepts
the same simple text lines as the control port.

## Some examples

Let's assume the SSE-Server is running on host www.example.org and
listening on port 8080 for URLs like this:

   https://www.example.org:8080/my/sse/server

Then a client can subscribe to, e.g., the channels ‘color’, ‘number’
and ‘page’ by adding those to the path. The order does not matter:

   https://www.example.org:8080/my/se/server/color/number/page

In SSE, each message must have a type (the event type) and a content
(the event data), both of which are arbitrary text string. To send a
message of type ‘message’ with content ‘first’ to all clients on the
‘color’ channel, make a GET request to this URL:

   https://www.example.org:8080/my/sse/server/color?message=first

You can send multiple messages to multiple channels in one go:

   https://www.example.org:8080/my/sse/server/color/page?q1=go&q2=end

This sends two messages (type ‘q1’ with data ‘go’ and type ‘q2’ with
data ‘end’) to both the color and page channels. (Clients subscribed
to both channels will only get the messages once.)

To send those same two messages via the FIFO or the control port,
write these four lines to them:

   color/q1 = go
   page/q1 = go
   color/q2 = end
   page/q2 = end

(Except that, unlike with the URL query above, clients subscribed to
both the ‘color’ and ‘page’ channels will get the messages twice.)

White space at the start and end, and around the ‘=’, will be ignored.

To do this on the command line on Unix, assuming the FIFO is called ‘sse.fifo’, use a command such as this:

   echo "color/q1 = go" > sse.fifo

On the FIFO and the control port, the event type ‘message’ is the
default and can be omitted. E.g., the following two lines are
equivalent.

   channel/message = some data here
   channel = some data here

## Commands

Apart from messages, the server accepts two commands:

‘status’: This puts some information in the log file (if logging is
enabled) with information about currently connected clients.

‘halt’: This disconnects all clients and stops the server. E.g.:

   echo halt > sse/fifo

These commands can be given on the FIFO and the control port. They can
be given as a query on the HTTP port only if exicitly enabled.

## Running under Apache

You can use Apache as a reverse proxy to an SSE-Server (for the HTTP
port only, the control port does not use HTTP). This can be useful
when running on a system that already has Apache running on the
desired port, or to use Apache for authentication.

Choose a path prefix, e.g., ‘/my/sse/server’, choose a port (e.g., the
default, 8080) and put this in the Apache configuration:

   <Location "/my/sse/server">
      ProxyPass http://localhost:8080/my/sse/server
   </Location>

Then run the server, e.g. like this:

   sse-server -f sse-server.fifo -P 8085 -l sse-server.log

And use it as normal, but on port 80 (http) or 443 (https), not 8080:

   https://www.example.org/my/sse/server/channel71

