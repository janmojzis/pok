# client - server connection
The utility basically creates an encrypted connection between the client and
the server.

## authorized connection
The client authenticates using its authorization public-key, and the server (or
an application running on the server) applies its security policies based on
that public key.
The server exchanges the authorization public-key hash with the application
via the env. environment variable.
Examples:
  - access to an IMAP server, where the IMAP application extracts the public-key
    hash and grants access to the IMAP account paired with that public-key
  - access to an SMTP server, outgoing SMTP server allows/rejects sending email
    from the client with given public-key
  - video conferencing applications (server = calling party, client = caller),
    The server application will popup a message that a client with the given
    public-key is trying to make call, whether to accept or reject it. And if
    user accepts, then the call will start.

# client - forwarder - server connection
In this case, the `forwarder` forwards packets between the client and the server
and helps create connections in more complicated networks, e.g. when the server
is behind NAT.

## public-key based forwarding
The server establishes an encrypted and authorized "backend" connection to
the forwarder. Server uses its long-term key for authorization.
![server-forwarder](img/server-forwarder.jpg)

And when a backend connection is established, then the forwarder knows:
  - server's long-term public-key hash
  - server's backend connection (UDP IP + PORT)

Now can forwarder apply it's policies:
  - first, forwarder checks whether the forwarding service is enabled for
    the server with this public-key
  - second, if forwarding is enabled, it will start forwarding client packets
    to the backed connection created by the server with the given public-key

![client-server](img/client-server.jpg)
