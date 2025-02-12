# ZF FROST Server (frostd)

One challenge for using FROST is allowing participants to communicate securely
with one another. Devices are usually behind firewalls and NATs, which make
direct connections hard.

To mitigate this issue and to make it easier to use FROST, the ZF FROST Server
(frostd) was created. It is a JSON-HTTP server with a small API to allow
participants to create signing sessions and to communicate with one another.

It works like this:

- Clients (coordinator or participants) authenticate to the server using a key
  pair, which will likely be the same key pair they use to end-to-end encrypt
  messages.
- The Coordinator creates a session, specifying the public keys of the
  participants.
- Participants list sessions they're participating in, and choose the proceed
  with the signing session.
- Coordinator and Participants run the FROST protocol, end-to-end encrypting
  messages and sending them to the server.
- The Coordinator closes the session.

Note that the server doesn't really care about the particular key pair being
used; it is only used to enforce who can send messages to who.

## Compiling, Running and Deploying

You will need to have [Rust and
Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)
installed. Run:

```
cargo install --git https://github.com/ZcashFoundation/frost-zcash-demo.git --locked frostd
```

The `frostd` binary will be installed [per `cargo`
config](https://doc.rust-lang.org/cargo/commands/cargo-install.html#description)
and it will likely be in your `$PATH`, so you can run by simply running
`frostd`.

To deploy the FROST Server, **you need TLS/HTTPS certificates**. We strongly
recommend using a reverse proxy such as `nginx` to handle TLS and to also add
denial of service protections. In that case, use the `--no-tls-very-insecure`
flag in `frostd` and make `nginx` connect to it (see example config below).

If you want to expose `frostd` directly, use the `--tls-cert` and
`--tls-key` to specify the paths of the PEM-encoded certificate and key. You can
use [Let's Encrypt](https://letsencrypt.org/) to get a free certificate.


### Local Testing

For local testing, you can use the [`mkcert`
tool](https://github.com/FiloSottile/mkcert). Install it and run:

```
mkcert -install
mkcert localhost 127.0.0.1 ::1
```

Then start the server with:

```
frostd  --tls-cert localhost+2.pem --tls-key localhost+2-key.pem
```


### Sample nginx Config

This is a sample nginx config file tested in a Ubuntu deployment (i.e. it
assumes it's in a `http` block and it's included by `/etc/nginx/nginx.conf`);
copy it to `/etc/nginx/sites-enabled/frostd` and run `sudo service nginx
restart`.

The config assumes the certificates were copied to `/etc/ssl`.


```
limit_req_zone $binary_remote_addr zone=challenge:10m rate=30r/m;
limit_req_zone $binary_remote_addr zone=create:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=other:10m rate=240r/m;
limit_conn_zone $binary_remote_addr zone=addr:10m;

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    ssl_certificate /etc/ssl/localhost+2.pem;
    ssl_certificate_key /etc/ssl/localhost+2-key.pem;
    ssl_protocols TLSv1.3;
    ssl_ecdh_curve X25519:prime256v1:secp384r1;
    ssl_prefer_server_ciphers off;

    server_name localhost;

    client_body_timeout 5s;
    client_header_timeout 5s;

    location / {
        proxy_pass http://127.0.0.1:2744;
        limit_req zone=other burst=5;
        limit_conn addr 10;
    }
    location /challenge {
        proxy_pass http://127.0.0.1:2744/challenge;
        limit_req zone=challenge burst=3;
        limit_conn addr 10;
    }
    location /create_new_session {
        proxy_pass http://127.0.0.1:2744/create_new_session;
        limit_req zone=create burst=3;
        limit_conn addr 10;
    }
}
```

## API

The API uses JSON/HTTP. All requests should have `Content-Type:
application/json`. Errors are returned with status code 500 and the content
body will have a JSON such as:

```
{ code: 1, msg: "error message" }
```

The
[codes](https://github.com/ZcashFoundation/frost-zcash-demo/blob/548a8a7329c6eed8180464662f430d12cd71dfcc/frostd/src/lib.rs#L95-L98)
are:

```
pub const INVALID_ARGUMENT: usize = 1;
pub const UNAUTHORIZED: usize = 2;
pub const SESSION_NOT_FOUND: usize = 3;
pub const NOT_COORDINATOR: usize = 4;
```


### Usage flow

For the Coordinator:

- Log in with `/challenge` and `/login`
- Create a new signing session with `/create_new_session`
- Wait for round 1 messages by repeatedly polling `/receive` each 2 seconds or longer
- Send round 2 messages by using `/send`
- Wait for round 2 message  by repeatedly polling `/receive` each 2 seconds or longer
- Close the session with `/close_session`

For Participants:

- Log in with `/challenge` and `/login`
- Wait for signing sessions with `/list_sessions`, either by the user's request or by repeatedly
  polling each 10 seconds or longer
- Get the session information with `/get_session_info`
- Show the user the session information (who the participants are) to select which
  session (if more than one)
- Send round 1 message by using `/send`
- Wait for round 2 message by repeatedly polling `/receive` each 2 seconds or longer
- Send round 2 message by using `/send`

```admonish info
**Polling** is not optimal. The server will support a better mechanism in the
future.
```

```admonish info
Selecting sessions is tricky. Ideally, the user should select what session
to proceed by checking the message being signed; however, that is usually
sent in Round 2. There are multiple ways to handle this:

- Simply show the users who are participants, hoping that is enough to
  disambiguate (we assume that concurrent signing sessions won't be that common)
- Quietly proceed with all sessions, and only prompt the user after the message
  is received. (It's harmless to do round 1 of FROST even if the user might
  not have agreed to sign the message yet.)
- Change the application so that the message is sent to the participants first
  (the server does not really care how the protocol is run).
```

```admonish critical
Always gather consent from the user by showing them the message before
signing it.
```

### `/challenge`

Input: empty

Sample output:

```
{"challenge":"2c5cdb6d-a7db-470e-9e6f-2a7062532825"}
```

Returns a challenge that the client will need to sign in order to authenticate.

### `/login`

To call `/login`, you will need to sign the challenge with XEdDSA, see
[example](https://github.com/ZcashFoundation/frost-zcash-demo/blob/548a8a7329c6eed8180464662f430d12cd71dfcc/frostd/tests/integration_tests.rs#L443-L476).
Sign the challenge UUID, converted to bytes.


Input sample:

```
{
  "challenge":"b771757e-085a-4a88-ab8f-28bd4ba67f3a",
  "pubkey":"f5bf1b8194e20ebdd28e662b1efcf1c5cd2aaade5d5dd83cf89b246b5492726b",
  "signature":"bba398d0963ab88e28134ad41c127eeee816a219838db01dd7bcd9d7fcd975f082330c134e6f7238580ba8434652aa116891495452d9048f5615e07f4ad6b204"
}
```

Output sample:

```
{"access_token":"061a18ba-2c3c-4685-a79e-2c0c93000af5"}
```

The returned access token must be included as a bearer token in an
`Authorization` header; e.g. `Authorization: Bearer
061a18ba-2c3c-4685-a79e-2c0c93000af5`.

Access tokens are currently valid for 1 hour. It's recommended to login at the
beginning of each FROST session; log in again if it needs to take longer.

### `/logout`

Input: empty (it will logout the authenticated user)

Output: empty

Logs out, invalidating the access token. Note that access tokens expire after
1 hour anyway.

### `/create_new_session`

Input sample:

```
{
  "pubkeys": [
    "3c9f4a3b2ae28c8e11fbc90b693a9712c181275fb4b554a140c68dc13cdd9b4c",
    "edbd661dec0a9d0468b4a166a4afa80560d769f6bcb152fb8f4224059329a518"
  ],
  message_count: 1,
}
```

Output sample:

```
{"session_id": "2c5cdb6d-a7db-470e-9e6f-2a7062532825"}
```

Creates a new session. The requesting user will be the Coordinator, and the
users with the hex-encoded public keys given in `pubkeys` will be the
participants (which might or might not include the Coordinator itself).

The `message_count` parameter allows signing more than one message in the same
signing session, which will save roundtrips. This does not impacts the server
itself and is used to signal the participants (via `/get_session_info`).

### `/list_sessions`

Input: empty (it will list for the authenticated user)

Output sample:

```
{"session_ids": ["2c5cdb6d-a7db-470e-9e6f-2a7062532825"]}
```

List the sessions IDs of the session a participant is in.

### `/get_session_info`

Input sample:

```{"session_id": "2c5cdb6d-a7db-470e-9e6f-2a7062532825"}```

Output sample:

```
{
  "message_count": 1,
  "pubkeys": [
    "3c9f4a3b2ae28c8e11fbc90b693a9712c181275fb4b554a140c68dc13cdd9b4c",
    "edbd661dec0a9d0468b4a166a4afa80560d769f6bcb152fb8f4224059329a518"
  ],
  "coordinator_pubkey": "3c9f4a3b2ae28c8e11fbc90b693a9712c181275fb4b554a140c68dc13cdd9b4c",
}
```

Returns information about the given session.

### `/send`

Input sample:

```
{
  "session_id": "2c5cdb6d-a7db-470e-9e6f-2a7062532825",
  "recipients": ["3c9f4a3b2ae28c8e11fbc90b693a9712c181275fb4b554a140c68dc13cdd9b4c"],
  "msg": "000102",
}
```

Output: empty

Sends a (hex-encoded) message to one or more participants. To send to the
Coordinator, pass an empty list in `recipients` (**do not** use the
Coordinator's public key, because that might be ambiguous if they're also a
Participant).

```admonish critical
Messages **MUST** be end-to-end encrypted between recipients. The server can't
enforce this and if you fail to encrypt them then the server could read
all the messages.
```

### `/receive`

Input sample:

```
{
  "session_id": "2c5cdb6d-a7db-470e-9e6f-2a7062532825",
  "as_coordinator": false,
}
```

Output sample:

```
{
  "msgs":[
    {
      "sender": "3c9f4a3b2ae28c8e11fbc90b693a9712c181275fb4b554a140c68dc13cdd9b4c",
      "msg": "000102",
    }
  ]
}
```

Receives messages sent to the requesting user. Note that if a user is both a
Coordinator and a Participant, it is not possible to distinguish if a message
received from them was sent as Coordinator or as a Participant. This does not
matter in FROST since this ambiguity never arises (Participants always receive
messages from the Coordinator, and vice-versa, except during DKG where there is
no Coordinator anyway).

### `/close_session`

Input sample:

```{"session_id": "2c5cdb6d-a7db-470e-9e6f-2a7062532825"}```

Output: empty

Closes the given session. Only the Coordinator who created the session can close
it. Sessions also expire by default after 24 hours.
