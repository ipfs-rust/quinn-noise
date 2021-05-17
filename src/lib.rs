mod aead;
mod dh;
mod keylog;
mod session;

pub use crate::aead::ChaCha8PacketKey;
pub use crate::keylog::{KeyLog, KeyLogFile};
pub use crate::session::{NoiseConfig, NoiseSession};
pub use ed25519_dalek::{Keypair, PublicKey};

// https://github.com/quicwg/base-drafts/wiki/QUIC-Versions
// reserved versions for quinn-noise 0xf0f0f2f[0-f]
pub const SUPPORTED_QUIC_VERSIONS: &[u32] = &[0xf0f0f2f0];
pub const DEFAULT_QUIC_VERSION: u32 = 0xf0f0f2f0;
