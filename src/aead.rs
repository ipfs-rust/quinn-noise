use bytes::BytesMut;
use chacha20poly1305::{
    aead::{AeadInPlace, NewAead},
    ChaCha8Poly1305, Key, Nonce, Tag,
};
use quinn_proto::crypto::{CryptoError, HeaderKey, KeyPair, PacketKey};

pub fn header_keypair() -> KeyPair<Box<dyn HeaderKey>> {
    KeyPair {
        local: Box::new(PlaintextHeaderKey),
        remote: Box::new(PlaintextHeaderKey),
    }
}

#[derive(Clone)]
pub struct ChaCha8PacketKey(ChaCha8Poly1305);

impl ChaCha8PacketKey {
    pub fn new(key: [u8; 32]) -> Self {
        let key = Key::from(key);
        Self(ChaCha8Poly1305::new(&key))
    }
}

impl PacketKey for ChaCha8PacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&packet.to_le_bytes());
        let nonce = Nonce::from(nonce);
        let (header, payload) = buf.split_at_mut(header_len);
        let (content, auth) = payload.split_at_mut(payload.len() - self.tag_len());
        let tag = self
            .0
            .encrypt_in_place_detached(&nonce, header, content)
            .unwrap();
        auth.copy_from_slice(&tag);
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&packet.to_le_bytes());
        let nonce = Nonce::from(nonce);
        let len = payload.len() - self.tag_len();
        let (content, tag) = payload.split_at_mut(len);
        let tag = Tag::from_slice(tag);
        self.0
            .decrypt_in_place_detached(&nonce, header, content, tag)
            .map_err(|_| CryptoError)?;
        payload.truncate(len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn confidentiality_limit(&self) -> u64 {
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        u64::MAX
    }
}

pub struct PlaintextHeaderKey;

impl HeaderKey for PlaintextHeaderKey {
    fn decrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

    fn encrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}

    fn sample_size(&self) -> usize {
        0
    }
}
