use bitcoin::{
    schnorr,
    secp256k1::{Message, Secp256k1},
    util::taproot,
};
use secp256k1_zkp::MusigAggNonce;
use swapper::taproot::TaprootContract;

use rand::thread_rng;

#[test]
fn musig_keygen_tapscript_spend() {
    let s = Secp256k1::new();
    let mut rng = thread_rng();

    let keypair = schnorr::KeyPair::new(&s, &mut rng);
    let oth_keypair = schnorr::KeyPair::new(&s, &mut rng);

    let pubkeys = [
        schnorr::PublicKey::from_keypair(&s, &keypair),
        schnorr::PublicKey::from_keypair(&s, &oth_keypair),
    ];
    let timelock_keypair = schnorr::KeyPair::new(&s, &mut rng);

    let mut contract = TaprootContract::with_musig_keygen(
        &s,
        keypair,
        &pubkeys,
        schnorr::PublicKey::from_keypair(&s, &timelock_keypair),
    )
    .unwrap();
    let mut oth_contract = TaprootContract::with_musig_keygen(
        &s,
        oth_keypair,
        &pubkeys,
        schnorr::PublicKey::from_keypair(&s, &timelock_keypair),
    )
    .unwrap();

    let _tweak_pub = contract.musig_pubkey_tweak_add(&s, &[42; 32]).unwrap();
    let _oth_tweak_pub = oth_contract.musig_pubkey_tweak_add(&s, &[69; 32]).unwrap();

    let msg = Message::from_slice(&[0; 32]).unwrap();

    contract
        .musig_nonce_gen(&s, /*session_id*/ &[1; 32], &msg, None)
        .unwrap();
    oth_contract
        .musig_nonce_gen(&s, /*session_id*/ &[1; 32], &msg, None)
        .unwrap();

    let agg_nonce = MusigAggNonce::new(
        &s,
        &[
            *contract.musig_pub_nonce().unwrap(),
            *oth_contract.musig_pub_nonce().unwrap(),
        ],
    )
    .unwrap();

    contract
        .musig_nonce_process(&s, &agg_nonce, &msg, None)
        .unwrap();
    oth_contract
        .musig_nonce_process(&s, &agg_nonce, &msg, None)
        .unwrap();

    let lock_sequence = 10;
    let leaf_version = taproot::LeafVersion::default();
    contract
        .musig_create_contract(&s, lock_sequence, leaf_version)
        .unwrap();
    oth_contract
        .musig_create_contract(&s, lock_sequence, leaf_version)
        .unwrap();
}
