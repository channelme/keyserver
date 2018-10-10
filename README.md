keyserver
=========

Keyserver is a key distribution mechanism for IoT like communicating
entities. It can be used to exchange keys for direct communication and
for publish/subscribe communication patterns. 

Usage
-----

Create a new keyserver:

```erlang
{ok, Pid} = keyserver:start(my_first_keyserver, CallbackModule, []),
```

This starts a new keyserver. In order to communicate with the
keyserver you must first know the public encryption key of the
keyserver and the name of the keyserver. All connection request to the
keyserver are encrypted with this key. The keyserver can decrypt the
connection request and register the entity.

The CallbackModule will be called to check if entities are allowed to
connect, publish, subscribe, or communicate directly.

```erlang
{ok, PubEncKey} = keyserver:public_enc_key(my_first_keyserver).
```

The public encryption key must be transport out of band to the
client. It is possible to this via a normal TLS connection or another
safe method.

After retrieving the public encryption key, a client can request a key
from the keyserver to communicate with another entity.

```erlang
Key = keyserver_crypto:generate_key(),
Nonce = keyserver_crypto:generate_nonce(),

{ok, _ServerNonce, {hello_response, KeyES, Nonce1}} =
    keyserver:connect_to_server(my_first_keyserver, "me", Key, Nonce, ServerEncKey).
```



...
