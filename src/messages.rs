use bitcoin::XOnlyPublicKey;
use secp256k1_zkp::{MusigPartialSignature, MusigPubNonce};

pub struct TaprootInit {
    pub keypath_key: XOnlyPublicKey,
    pub timelock_key: XOnlyPublicKey,
    pub lock_sequence: i64,
    pub output_key: XOnlyPublicKey,
    pub amount: u64,
}

pub struct TaprootPreSign {
    pub transaction: Transaction, 
}

pub struct TaprootSign {
    pub partial_nonce: MusigPubNonce,
    pub partial_sig: MusigPartialSignature,
}
