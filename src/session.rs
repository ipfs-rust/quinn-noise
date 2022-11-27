use crate::aead::{header_keypair, ChaCha8PacketKey, PlaintextHeaderKey};
use crate::dh::DiffieHellman;
use crate::keylog::KeyLog;
use ed25519_dalek::{Keypair, PublicKey};
use quinn_proto::crypto::{
    ClientConfig, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey, ServerConfig,
    Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, ConnectionId, Side, TransportError, TransportErrorCode};
use ring::aead;
use std::any::Any;
use std::io::Cursor;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use xoodoo::Xoodyak;

pub struct NoiseClientConfig {
    /// Keypair to use.
    pub keypair: Keypair,
    /// Optional private shared key usable as a password for private networks.
    pub psk: Option<[u8; 32]>,
    /// Enables keylogging for debugging purposes to the path provided by `SSLKEYLOGFILE`.
    pub keylogger: Option<Arc<dyn KeyLog>>,
    /// The remote public key. This needs to be set.
    pub remote_public_key: PublicKey,
    /// ALPN string to use.
    pub alpn: Vec<u8>,
}

impl From<NoiseClientConfig> for NoiseConfig {
    fn from(config: NoiseClientConfig) -> Self {
        Self {
            keypair: Some(config.keypair),
            psk: config.psk,
            keylogger: config.keylogger,
            remote_public_key: Some(config.remote_public_key),
            alpn: Some(config.alpn),
            supported_protocols: None,
        }
    }
}

pub struct NoiseServerConfig {
    /// Keypair to use.
    pub keypair: Keypair,
    /// Optional private shared key usable as a password for private networks.
    pub psk: Option<[u8; 32]>,
    /// Enables keylogging for debugging purposes to the path provided by `SSLKEYLOGFILE`.
    pub keylogger: Option<Arc<dyn KeyLog>>,
    /// Supported ALPN identifiers.
    pub supported_protocols: Vec<Vec<u8>>,
}

impl From<NoiseServerConfig> for NoiseConfig {
    fn from(config: NoiseServerConfig) -> Self {
        Self {
            keypair: Some(config.keypair),
            psk: config.psk,
            keylogger: config.keylogger,
            remote_public_key: None,
            alpn: None,
            supported_protocols: Some(config.supported_protocols),
        }
    }
}

/// Noise configuration struct.
#[derive(Default)]
pub struct NoiseConfig {
    /// Keypair to use.
    keypair: Option<Keypair>,
    /// Optional private shared key usable as a password for private networks.
    psk: Option<[u8; 32]>,
    /// Enables keylogging for debugging purposes to the path provided by `SSLKEYLOGFILE`.
    keylogger: Option<Arc<dyn KeyLog>>,
    /// The remote public key. This needs to be set.
    remote_public_key: Option<PublicKey>,
    /// ALPN string to use.
    alpn: Option<Vec<u8>>,
    /// Supported ALPN identifiers.
    supported_protocols: Option<Vec<Vec<u8>>>,
}

impl ClientConfig for NoiseConfig {
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn Session>, ConnectError> {
        Ok(Box::new(NoiseConfig::start_session(
            &self,
            Side::Client,
            params,
        )))
    }
}

impl ServerConfig for NoiseConfig {
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        Box::new(NoiseConfig::start_session(&self, Side::Server, params))
    }

    fn initial_keys(
        &self,
        _version: u32,
        _dst_cid: &ConnectionId,
        _side: Side,
    ) -> Result<Keys, quinn_proto::crypto::UnsupportedVersion> {
        Ok(Keys {
            header: header_keypair(),
            packet: KeyPair {
                local: Box::new(ChaCha8PacketKey::new([0; 32])),
                remote: Box::new(ChaCha8PacketKey::new([0; 32])),
            },
        })
    }

    fn retry_tag(&self, _version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        let mut pseudo_packet = Vec::with_capacity(packet.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(packet);

        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE);
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY).unwrap(),
        );

        let tag = key
            .seal_in_place_separate_tag(nonce, aead::Aad::from(pseudo_packet), &mut [])
            .unwrap();
        let mut result = [0; 16];
        result.copy_from_slice(tag.as_ref());
        result
    }
}

impl NoiseConfig {
    fn start_session(&self, side: Side, params: &TransportParameters) -> NoiseSession {
        let mut rng = rand_core::OsRng {};
        let s = if let Some(keypair) = self.keypair.as_ref() {
            Keypair::from_bytes(&keypair.to_bytes()).unwrap()
        } else {
            Keypair::generate(&mut rng)
        };
        let e = Keypair::generate(&mut rng);
        NoiseSession {
            xoodyak: Xoodyak::hash(),
            state: State::Initial,
            side,
            e,
            s,
            psk: self.psk.unwrap_or_default(),
            alpn: self.alpn.clone(),
            supported_protocols: self.supported_protocols.clone(),
            transport_parameters: *params,
            remote_transport_parameters: None,
            remote_e: None,
            remote_s: self.remote_public_key,
            zero_rtt_key: None,
            keylogger: self.keylogger.clone(),
        }
    }
}

impl Clone for NoiseConfig {
    fn clone(&self) -> Self {
        let keypair = self
            .keypair
            .as_ref()
            .map(|keypair| Keypair::from_bytes(&keypair.to_bytes()).unwrap());
        Self {
            keypair,
            psk: self.psk,
            keylogger: self.keylogger.clone(),
            remote_public_key: self.remote_public_key,
            alpn: self.alpn.clone(),
            supported_protocols: self.supported_protocols.clone(),
        }
    }
}

pub struct NoiseSession {
    xoodyak: Xoodyak,
    state: State,
    side: Side,
    e: Keypair,
    s: Keypair,
    psk: [u8; 32],
    alpn: Option<Vec<u8>>,
    supported_protocols: Option<Vec<Vec<u8>>>,
    transport_parameters: TransportParameters,
    remote_transport_parameters: Option<TransportParameters>,
    remote_e: Option<PublicKey>,
    remote_s: Option<PublicKey>,
    zero_rtt_key: Option<ChaCha8PacketKey>,
    keylogger: Option<Arc<dyn KeyLog>>,
}

impl NoiseSession {
    fn conn_id(&self) -> Option<&[u8; 32]> {
        match self.side {
            Side::Client => Some(self.e.public.as_bytes()),
            Side::Server => Some(self.remote_e.as_ref()?.as_bytes()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Initial,
    ZeroRtt,
    Handshake,
    OneRtt,
    Data,
}

fn connection_refused(reason: &str) -> TransportError {
    TransportError {
        code: TransportErrorCode::CONNECTION_REFUSED,
        frame: None,
        reason: reason.to_string(),
    }
}

impl NoiseSession {
    fn next_1rtt_keys0(&mut self) -> KeyPair<ChaCha8PacketKey> {
        if !self.is_handshaking() {
            self.xoodyak.ratchet();
        }
        let mut client = [0; 32];
        self.xoodyak.squeeze_key(&mut client);
        let mut server = [0; 32];
        self.xoodyak.squeeze_key(&mut server);
        if let Some(keylogger) = self.keylogger.as_ref() {
            keylogger.log("CLIENT_KEY", self.conn_id().unwrap(), &client[..]);
            keylogger.log("SERVER_KEY", self.conn_id().unwrap(), &server[..]);
        }
        let client = ChaCha8PacketKey::new(client);
        let server = ChaCha8PacketKey::new(server);
        match self.side {
            Side::Client => KeyPair {
                local: client,
                remote: server,
            },
            Side::Server => KeyPair {
                local: server,
                remote: client,
            },
        }
    }
}

impl Session for NoiseSession {
    fn initial_keys(&self, _: &ConnectionId, _: Side) -> Keys {
        Keys {
            header: header_keypair(),
            packet: KeyPair {
                local: Box::new(ChaCha8PacketKey::new([0; 32])),
                remote: Box::new(ChaCha8PacketKey::new([0; 32])),
            },
        }
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let key = self.next_1rtt_keys0();
        Some(KeyPair {
            local: Box::new(key.local),
            remote: Box::new(key.remote),
        })
    }

    fn read_handshake(&mut self, handshake: &[u8]) -> Result<bool, TransportError> {
        tracing::trace!("read_handshake {:?} {:?}", self.state, self.side);
        match (self.state, self.side) {
            (State::Initial, Side::Server) => {
                // protocol identifier
                if handshake.is_empty() {
                    return Err(connection_refused("invalid crypto frame"));
                }
                let (len, rest) = handshake.split_at(1);
                let len = len[0] as usize;
                if rest.len() < len {
                    return Err(connection_refused("invalid crypto frame"));
                }
                let (protocol_id, rest) = rest.split_at(len);
                if protocol_id != b"Noise_IKpsk1_Edx25519_ChaCha8Poly" {
                    return Err(connection_refused("unsupported protocol id"));
                }
                self.xoodyak.absorb(protocol_id);
                // e
                if rest.len() < 32 {
                    return Err(connection_refused("invalid crypto frame"));
                }
                let (e, rest) = rest.split_at(32);
                self.xoodyak.absorb(e);
                let e = PublicKey::from_bytes(e)
                    .map_err(|_| connection_refused("invalid ephemeral public key"))?;
                self.remote_e = Some(e);
                // s
                self.xoodyak.absorb(self.s.public.as_bytes());
                // es
                let es = self.s.diffie_hellman(&e);
                self.xoodyak.absorb(&es);
                // initialize keyed session transcript
                let mut key = [0; 32];
                self.xoodyak.squeeze(&mut key);
                self.xoodyak = Xoodyak::keyed(&key, None, None, None);
                // s
                if rest.len() < 32 {
                    return Err(connection_refused("invalid crypto frame"));
                }
                let (remote_s, rest) = rest.split_at(32);
                let mut s = [0; 32];
                self.xoodyak.decrypt(remote_s, &mut s);
                let s = PublicKey::from_bytes(&s)
                    .map_err(|_| connection_refused("invalid static public key"))?;
                self.remote_s = Some(s);
                // ss
                let ss = self.s.diffie_hellman(&s);
                self.xoodyak.absorb(&ss);
                // psk
                self.xoodyak.absorb(&self.psk);
                // alpn
                if rest.is_empty() {
                    return Err(connection_refused("invalid crypto frame"));
                }
                let (len, rest) = rest.split_at(1);
                let len = len[0] as usize;
                if rest.len() < len {
                    return Err(connection_refused("invalid crypto frame"));
                }
                let (alpn, rest) = rest.split_at(len);
                let mut alpn = alpn.to_vec();
                self.xoodyak.decrypt_in_place(&mut alpn);
                let is_supported = self
                    .supported_protocols
                    .as_ref()
                    .expect("invalid config")
                    .iter()
                    .any(|proto| proto.as_slice() == alpn);
                if !is_supported {
                    return Err(connection_refused("unsupported alpn"));
                }
                self.alpn = Some(alpn);
                // transport parameters
                if rest.len() < 16 {
                    return Err(connection_refused("invalid crypto frame"));
                }
                let (params, auth) = rest.split_at(rest.len() - 16);
                let mut transport_parameters = vec![0; params.len()];
                self.xoodyak.decrypt(params, &mut transport_parameters);
                // check tag
                let mut tag = [0; 16];
                self.xoodyak.squeeze(&mut tag);
                if !bool::from(tag.ct_eq(auth)) {
                    return Err(connection_refused("invalid authentication tag"));
                }
                self.remote_transport_parameters = Some(TransportParameters::read(
                    Side::Server,
                    &mut Cursor::new(&mut transport_parameters),
                )?);
                self.state = State::ZeroRtt;
                Ok(true)
            }
            (State::Handshake, Side::Client) => {
                // e
                if handshake.len() < 32 {
                    return Err(connection_refused("invalid crypto frame"));
                }
                let (remote_e, rest) = handshake.split_at(32);
                let mut e = [0; 32];
                self.xoodyak.decrypt(remote_e, &mut e);
                let e = PublicKey::from_bytes(&e)
                    .map_err(|_| connection_refused("invalid ephemeral public key"))?;
                self.remote_e = Some(e);
                // ee
                let ee = self.e.diffie_hellman(&e);
                self.xoodyak.absorb(&ee);
                // se
                let se = self.s.diffie_hellman(&e);
                self.xoodyak.absorb(&se);
                // transport parameters
                if rest.len() < 16 {
                    return Err(connection_refused("invalid crypto frame"));
                }
                let (params, auth) = rest.split_at(rest.len() - 16);
                let mut transport_parameters = vec![0; params.len()];
                self.xoodyak.decrypt(params, &mut transport_parameters);
                // check tag
                let mut tag = [0; 16];
                self.xoodyak.squeeze(&mut tag);
                if !bool::from(tag.ct_eq(auth)) {
                    return Err(connection_refused("invalid authentication tag"));
                }
                self.remote_transport_parameters = Some(TransportParameters::read(
                    Side::Client,
                    &mut Cursor::new(&mut transport_parameters),
                )?);
                self.state = State::OneRtt;
                Ok(true)
            }
            _ => Err(TransportError {
                code: TransportErrorCode::CONNECTION_REFUSED,
                frame: None,
                reason: "unexpected crypto frame".to_string(),
            }),
        }
    }

    fn write_handshake(&mut self, handshake: &mut Vec<u8>) -> Option<Keys> {
        tracing::trace!("write_handshake {:?} {:?}", self.state, self.side);
        match (self.state, self.side) {
            (State::Initial, Side::Client) => {
                // protocol identifier
                let protocol_id = b"Noise_IKpsk1_Edx25519_ChaCha8Poly";
                self.xoodyak.absorb(protocol_id);
                handshake.extend_from_slice(&[protocol_id.len() as u8]);
                handshake.extend_from_slice(protocol_id);
                // e
                self.xoodyak.absorb(self.e.public.as_bytes());
                handshake.extend_from_slice(self.e.public.as_bytes());
                // s
                let s = self.remote_s.unwrap();
                self.xoodyak.absorb(s.as_bytes());
                // es
                let es = self.e.diffie_hellman(&s);
                self.xoodyak.absorb(&es);
                // initialize keyed session transcript
                let mut key = [0; 32];
                self.xoodyak.squeeze(&mut key);
                self.xoodyak = Xoodyak::keyed(&key, None, None, None);
                // s
                let mut s = [0; 32];
                self.xoodyak.encrypt(self.s.public.as_bytes(), &mut s);
                handshake.extend_from_slice(&s);
                // ss
                let s = self.remote_s.unwrap();
                let ss = self.s.diffie_hellman(&s);
                self.xoodyak.absorb(&ss);
                // psk
                self.xoodyak.absorb(&self.psk);
                // alpn
                let alpn = self.alpn.as_ref().expect("invalid config");
                handshake.extend_from_slice(&[alpn.len() as u8]);
                let pos = handshake.len();
                handshake.extend_from_slice(alpn);
                self.xoodyak.encrypt_in_place(&mut handshake[pos..]);
                // transport parameters
                let mut transport_parameters = vec![];
                self.transport_parameters.write(&mut transport_parameters);
                self.xoodyak.encrypt_in_place(&mut transport_parameters);
                handshake.extend_from_slice(&transport_parameters);
                // tag
                let mut tag = [0; 16];
                self.xoodyak.squeeze(&mut tag);
                handshake.extend_from_slice(&tag);
                // 0-rtt
                self.state = State::ZeroRtt;
                None
            }
            (State::ZeroRtt, _) => {
                let packet = self.next_1rtt_keys0();
                self.state = State::Handshake;
                self.zero_rtt_key = Some(packet.local.clone());
                Some(Keys {
                    header: header_keypair(),
                    packet: KeyPair {
                        local: Box::new(packet.local),
                        remote: Box::new(packet.remote),
                    },
                })
            }
            (State::Handshake, Side::Server) => {
                // e
                let mut e = [0; 32];
                self.xoodyak.encrypt(self.e.public.as_bytes(), &mut e);
                handshake.extend_from_slice(&e);
                // ee
                let ee = self.e.diffie_hellman(&self.remote_e.unwrap());
                self.xoodyak.absorb(&ee);
                // se
                let se = self.e.diffie_hellman(&self.remote_s.unwrap());
                self.xoodyak.absorb(&se);
                // transport parameters
                let mut transport_parameters = vec![];
                self.transport_parameters.write(&mut transport_parameters);
                self.xoodyak.encrypt_in_place(&mut transport_parameters);
                handshake.extend_from_slice(&transport_parameters);
                // tag
                let mut tag = [0; 16];
                self.xoodyak.squeeze(&mut tag);
                handshake.extend_from_slice(&tag);
                // 1-rtt keys
                let packet = self.next_1rtt_keys().unwrap();
                self.state = State::Data;
                Some(Keys {
                    header: header_keypair(),
                    packet,
                })
            }
            (State::OneRtt, _) => {
                let packet = self.next_1rtt_keys().unwrap();
                self.state = State::Data;
                Some(Keys {
                    header: header_keypair(),
                    packet,
                })
            }
            _ => None,
        }
    }

    fn is_handshaking(&self) -> bool {
        self.state != State::Data
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        Some(Box::new(self.remote_s?))
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        if self.state == State::Handshake && self.side == Side::Client {
            Ok(Some(self.transport_parameters))
        } else {
            Ok(self.remote_transport_parameters)
        }
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        Some(Box::new(self.alpn.clone()?))
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        let mut xoodyak = self.xoodyak.clone();
        xoodyak.absorb(label);
        xoodyak.absorb(context);
        xoodyak.squeeze_key(output);
        Ok(())
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        Some((
            Box::new(PlaintextHeaderKey),
            Box::new(self.zero_rtt_key.clone()?),
        ))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        Some(true)
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let tag_start = match payload.len().checked_sub(16) {
            Some(x) => x,
            None => return false,
        };

        let mut pseudo_packet =
            Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);

        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE);
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY).unwrap(),
        );

        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        key.open_in_place(nonce, aead::Aad::from(aad), tag).is_ok()
    }
}

const RETRY_INTEGRITY_KEY: [u8; 16] = [
    0xcc, 0xce, 0x18, 0x7e, 0xd0, 0x9a, 0x09, 0xd0, 0x57, 0x28, 0x15, 0x5a, 0x6c, 0xb9, 0x6b, 0xe1,
];
const RETRY_INTEGRITY_NONCE: [u8; 12] = [
    0xe5, 0x49, 0x30, 0xf9, 0x7f, 0x21, 0x36, 0xf0, 0x53, 0x0a, 0x8c, 0x1c,
];
