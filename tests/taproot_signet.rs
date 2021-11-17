#[cfg(feature = "signet")]
mod taproot_signet_tests {
    use bitcoin::{
        blockdata::{opcodes, script::Builder, transaction::SigHashType},
        consensus,
        hashes::{hex::ToHex, Hash},
        schnorr,
        secp256k1::{Message, Secp256k1, SecretKey},
        util::{sighash, taproot},
        OutPoint, Transaction, TxIn, TxOut,
    };
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use rand::{thread_rng, RngCore};
    use secp256k1_zkp::MusigAggNonce;

    use swapper::{taproot::TaprootContract, Error};

    struct SignetClient<'c>(&'c Client);
    const WAL_NAME: &'static str = "cs_signet_test";

    fn setup_wallets<'c>(rpc: &'c Client) -> Result<SignetClient<'c>, Error> {
        match rpc.load_wallet(WAL_NAME) {
            Ok(_) => Ok(SignetClient(rpc)),
            Err(_) => {
                rpc.create_wallet(WAL_NAME, Some(true), Some(true), None, Some(false))?;
                Ok(SignetClient(rpc))
            }
        }
    }

    impl<'c> Drop for SignetClient<'c> {
        fn drop(&mut self) {
            self.0.unload_wallet(Some(WAL_NAME)).unwrap_or(());
        }
    }

    #[test]
    fn taproot_key_spend() -> Result<(), Error> {
        let url = "http://127.0.0.1:18332";
        let user = "coinswap_rpc_test";
        let pass = "coinswap_rpc_pass";

        let rpc = Client::new(&url, Auth::UserPass(user.to_owned(), pass.to_owned()))?;

        let s = Secp256k1::new();
        let mut rng = thread_rng();

        let _e2e_cli = setup_wallets(&rpc);

        let sk = SecretKey::from_slice(&[
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x6d, 0x6f, 0x6f, 0x6e, 0x73, 0x68, 0x6f, 0x74,
        ])
        .unwrap();
        let funder_keypair = schnorr::KeyPair::from_secret_key(&s, sk);
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

        let lock_sequence = 10;
        let leaf_version = taproot::LeafVersion::default();
        contract
            .musig_create_contract(&s, lock_sequence, leaf_version)
            .unwrap();
        oth_contract
            .musig_create_contract(&s, lock_sequence, leaf_version)
            .unwrap();

        let _tweak_agg_a =
            contract.musig_pubkey_tweak_add(&s, contract.tap_tweak().unwrap().as_inner())?;
        let _tweak_agg_b = oth_contract
            .musig_pubkey_tweak_add(&s, oth_contract.tap_tweak().unwrap().as_inner())?;

        assert_eq!(
            schnorr::PublicKey::from(_tweak_agg_a),
            contract.output_key()?
        );
        assert_eq!(
            schnorr::PublicKey::from(_tweak_agg_b),
            contract.output_key()?
        );

        let address = contract.address(&s).unwrap();
        let funder_address = bitcoin::Address::p2tr(
            s.clone(),
            schnorr::PublicKey::from_keypair(&s, &funder_keypair),
            None,
            bitcoin::Network::Signet,
        );

        println!("funder address: {}", funder_address);

        /*
        // Get a coinbase transaction from one of the blocks we just mined
        let block = rpc.get_block(&blockhashes[0])?;
        println!("block:\n\t{:?}\n", block);

        let tx_in = &block.txdata[0];
        println!("utxo:\n\t{:#?}\n", tx_in.output);
        println!(
            "output key: {}\n",
            contract.output_key()?.serialize().to_hex()
        );

        // For script path spend:
        //
        // witness: <signature-timelock> <tapleaf-timelock-script> <control-block>
        // scriptPubKey: <segwit-v1> <internal-key>
        //
        // TxIn {
        //   witness: vec![<signature-timelock> <tapleaf-timelock-script> <control-block>],
        //   ...
        // }
        //
        // For key path spend:
        //
        // witness: <signature>
        // scriptPubKey: <segwit-v1> <output-key>
        //
        // TxIn {
        //   witness: vec![<signature>],
        //   ...
        // }
        //let script_pubkey = &tx_in.output[0].script_pubkey;
        let time_pubkey = schnorr::PublicKey::from_keypair(&s, &timelock_keypair);
        let script_pubkey = Builder::new()
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .push_schnorr_key(&time_pubkey)
            .into_script();


        let output = [TxOut {
            value: 1729,
            script_pubkey: script_pubkey.clone(),
        }]
        .to_vec();

        let input = [TxIn {
            previous_output: OutPoint::new(tx_in.txid(), 0),
            ..Default::default()
        }]
        .to_vec();

        let mut tx = Transaction {
            version: tx_in.version,
            lock_time: tx_in.lock_time,
            input,
            output,
        };

        let msg = Message::from_slice(
            sighash::SigHashCache::new(&tx).taproot_signature_hash(
                0,
                &sighash::Prevouts::All(&tx_in.output[..1]),
                None,
                None,
                SigHashType::All.into(),
            )?
            .into_inner()
            .as_ref(),
        )
        .unwrap();
        println!("scriptHash: {:?}\n", msg);

        let mut session_id = [0; 32];
        rng.fill_bytes(&mut session_id);
        // generate Musig2 partial nonces
        contract
            .musig_nonce_gen(&s, &session_id, &msg, None)
            .unwrap();
        oth_contract
            .musig_nonce_gen(&s, &session_id, &msg, None)
            .unwrap();

        // compute aggregate Musig2 nonce
        let agg_nonce = MusigAggNonce::new(
            &s,
            &[
                *contract.musig_pub_nonce().unwrap(),
                *oth_contract.musig_pub_nonce().unwrap(),
            ],
        )
        .unwrap();

        // process the nonce to create the Musig2 signing session
        contract
            .musig_nonce_process(&s, &agg_nonce, &msg, None)
            .unwrap();
        oth_contract
            .musig_nonce_process(&s, &agg_nonce, &msg, None)
            .unwrap();

        let partial_sigs = [
            contract.musig_partial_sign(&s)?,
            oth_contract.musig_partial_sign(&s)?,
        ];
        let sig = contract.musig_partial_sig_agg(&s, partial_sigs.as_ref())?;

        // Verify aggregate signature is a valid Schnorr signature under the tweaked aggregate
        // public key
        assert!(s
            .schnorrsig_verify(&sig, &msg, &contract.output_key()?)
            .is_ok());

        tx.input[0].witness = [consensus::encode::serialize(sig.as_ref())].to_vec();

        let _hashes = rpc.generate_to_address(100, &address)?;

        // FIXME: errors out with "non-mandatory-script-verify-flag (Invalid Schnorr signature)"
        // what is causing signature verification to fail?
        let _txid_out = rpc.send_raw_transaction(&tx)?;

        let _hashes = rpc.generate_to_address(1, &address)?;
        */

        // FIXME:
        //   verify the transaction
        //   broadcast and mine transaction
        //   verify transaction output spendable

        Ok(())
    }
}
