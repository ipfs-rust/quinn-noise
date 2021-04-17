# Noise for the quinn quic implementation

## Handshake pattern

The IK handshake pattern is used with an optional psk. The psk allows for private
p2p networks using a pre shared key. In a p2p context the static keys are known and
the IK handshake allows for 0-rtt encryption. Identity hiding isn't a concern in
many p2p networks.

```
IK[psk1]:
    <- s
    ...
    -> e, es, s, ss, [psk] || client transport parameters
    <- e, ee, se           || server transport parameters
```

## Identity and key exchange

Signing keys are used as identities in p2p networks. Because the IK handshake required prior
knowledge of the handshake key, the signing key is reused for the key exchange. An ed25519 key
is converted to an x25519 key using the algorithm as implemented by libsodium.

## Handshake session

Using xoodyak a finalist in the light weight crypto competition we use the following
sequence of operations for deriving the 0rtt-key, 1rtt-key and next-1rtt-key. For fast
authenticated encryption a chacha8poly1309 cipher is used.

```
Initial:
  | Cyclist({}, {}, {})
p | Absorb("Noise_IKpsk1_Edx25519_ChaCha8Poly")
p | Absorb(e)
  | Absorb(s)
  | Absorb(es)
  | key = Squeeze(32)
Handshake:
  | Cyclist(key, {}, {})
c | c = Encrypt(s)
  | Absorb(ss)
  | Absorb(psk)
c | c = Encrypt(client_transport_parameters)
t | t = Squeeze(16)
  | initiator-0rtt-key = SqueezeKey(32)
  | responder-0rtt-key = SqueezeKey(32)
...
Handshake:
c | Encrypt(e)
  | Absorb(ee)
  | Absorb(se)
c | c = Encrypt(server_transport_parameters)
t | t = Squeeze(16)
  | initiator-1rtt-key = SqueezeKey(32)
  | responder-1rtt-key = SqueezeKey(32)
...
  | Ratchet()
  | initiator-next-1rtt-key = SqueezeKey(32)
  | responder-next-1rtt-key = SqueezeKey(32)
```
