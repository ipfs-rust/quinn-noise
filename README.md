# Noise for the quinn quic implementation

## Handshake pattern

The IK handshake pattern is used with an optional psk. The psk allows for private
p2p networks using a pre shared key. In a p2p context the static keys are known and
the IK handshake allows for 0-rtt encryption. Identity hiding isn't a concern in
many p2p networks.

```
IKpsk1:
    <- s
    ...
    -> e, es, s, ss, psk  || client transport parameters || 0rtt-data
    <- e, ee, se          || server transport parameters || 1rtt-data
```

## Identity and key exchange

Signing keys are used as identities in p2p networks. Because the IK handshake requires prior
knowledge of the handshake key, the signing key is reused for the key exchange. An ed25519 key
is converted to an x25519 key using the algorithm as implemented by libsodium.

NOTE: while it is likely ok to reuse the key for singing and diffie hellman it is strongly advised
not to reuse the key for other protocols like VRF or threshold signatures.

## Crypto algorithms

Using xoodyak (a finalist in the on-going NIST light weight crypto competition), the following
sequence of operations are performed for deriving the 0rtt-key, 1rtt-key and next-1rtt-key. For
fast authenticated encryption a chacha8poly1305 cipher is used.

## Session

The session transcript is initialized with the protocol identifier. The client ephemeral and server
static public keys, and the es dh are absorbed into the session transcript. From this session transcript
a session identifier is extracted which is used to initialize a keyed session transcript as per the
xoodyak paper section 3.3 authenticated encryption with a common secret. The encrypted client static
public key, the ss dh and the psk which defaults to [0; 32] if none was provided are added to the
session transcript. Then the encrypted ALPN string used to identify the application protocol and the
encrypted client transport parameters as defined by the quic spec are added to the transcript. Common
ALPN strings are `h3` for web or `libp2p` for libp2p applications. Finally an authentication tag for
the crypto frame and 0-rtt keys are extracted.

The initial packet's crypto frame contains the protocol identifier, the client ephemeral public
key, the encrypted client static public key, the encrypted ALPN identifier, the encrypted client
transport parameters and an authentication tag. After the initial packet 0-rtt packets can be sent
using the extracted 0-rtt key without having to wait for a response from the server.

```
Initial:
  | Cyclist({}, {}, {})
p | Absorb("Noise_IKpsk1_Edx25519_ChaCha8Poly")
p | Absorb(e)
  | Absorb(s)
  | Absorb(es)
  | key = Squeeze(32)
  | Cyclist(key, {}, {})
c | Encrypt(s)
  | Absorb(ss)
  | Absorb(psk)
c | Encrypt(alpn)
c | Encrypt(client_transport_parameters)
t | Squeeze(16)
  | initiator-0rtt-key = SqueezeKey(32)
  | responder-0rtt-key = SqueezeKey(32)
```

After receiving an initial packet the server produces a handshake packet containing the encrypted
server ephemeral public key and the encrypted server transport parameters. After the handshake
packet 1-rtt packets can be sent. Once all 0-rtt packets have been acked the keys are discarded.

```
Handshake:
c | Encrypt(e)
  | Absorb(ee)
  | Absorb(se)
c | Encrypt(server_transport_parameters)
t | Squeeze(16)
  | initiator-1rtt-key = SqueezeKey(32)
  | responder-1rtt-key = SqueezeKey(32)
```

During the transport session the 1-rtt keys might need to be rotated. This happens when approaching
`u64::MAX` sent packets or if forced by the connection. See the quic spec for details.

```
Key rotation:
  | Ratchet()
  | initiator-next-1rtt-key = SqueezeKey(32)
  | responder-next-1rtt-key = SqueezeKey(32)
```

## QUIC version

Reserved versions for `quinn-noise` are `0xf0f0f2f[0-f]` [0]. Currently only `0xf0f0f2f0` is a
valid `quinn-noise` version.

- [0] https://github.com/quicwg/base-drafts/wiki/QUIC-Versions

## Header protection

Header protection/obfuscation serves to prevent middle boxes from reading the header. Modification
is not possible since the header is passed as associated data to the cipher. The idea is that if
the header changes in a future quic version, middle boxes may drop the packets because they can't
read the header. But header protection/obfuscation only makes it harder not impossible. Due to
being questionable if it serves it's purpose it was decided that no header obfuscation is applied.

## Retry mechanism

The retry mechanism is identical to what is specified in the quic-tls spec.

## License

MIT OR Apache-2.0
