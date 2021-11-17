#[cfg(feature = "regtest")]
mod taproot_regtest_tests {
    use bitcoin::{
        blockdata::{opcodes, script::Builder},
        consensus,
        hashes::{hex::ToHex, Hash},
        secp256k1::{KeyPair, Message, Secp256k1, SecretKey, XOnlyPublicKey},
        util::{sighash, taproot},
        OutPoint, Transaction, TxIn, TxOut,
    };
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use rand::{thread_rng, RngCore};
    use secp256k1_zkp::MusigAggNonce;

    use swapper::{taproot::TaprootContract, Error};

    struct RegtestClient<'c> {
        client: &'c Client,
        wallet_name: &'static str,
    }

    fn setup_wallets<'c>(
        client: &'c Client,
        wallet_name: &'static str,
    ) -> Result<RegtestClient<'c>, Error> {
        match client.load_wallet(wallet_name) {
            Ok(_) => Ok(RegtestClient {
                client,
                wallet_name,
            }),
            Err(_) => {
                client.create_wallet(wallet_name, Some(true), Some(true), None, Some(false))?;
                Ok(RegtestClient {
                    client,
                    wallet_name,
                })
            }
        }
    }

    impl<'c> Drop for RegtestClient<'c> {
        fn drop(&mut self) {
            self.client
                .unload_wallet(Some(self.wallet_name))
                .unwrap_or(());
        }
    }

    // Need to combine RPC tests to avoid race conditions when generating blocks
    #[test]
    fn taproot_key_and_script_spends() -> Result<(), Error> {
        let url = "http://127.0.0.1:28332";
        let user = "coinswap_rpc_test";
        let pass = "coinswap_rpc_pass";

        let rpc = Client::new(&url, Auth::UserPass(user.to_owned(), pass.to_owned()))?;

        let s = Secp256k1::new();
        let mut rng = thread_rng();

        let _e2e_cli = setup_wallets(&rpc, "taproot_regtest_key_and_script_spend")?;

        let sk = SecretKey::from_slice(&[
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x6d, 0x6f, 0x6f, 0x6e, 0x6e, 0x6f, 0x6f, 0x6d,
        ])?;
        let mut funder_keypair = KeyPair::from_secret_key(&s, sk);

        // Mine blocks to P2TR address
        let funder_pubkey = XOnlyPublicKey::from_keypair(&s, &funder_keypair);
        let funder_taproot =
            taproot::TaprootSpendInfo::new_key_spend(&s, funder_pubkey.clone(), None);
        let funder_address =
            bitcoin::Address::p2tr(&s, funder_pubkey, None, bitcoin::Network::Regtest);

        let spend_keypair = KeyPair::new(&s, &mut rng);
        let spend_pubkey = XOnlyPublicKey::from_keypair(&s, &spend_keypair);
        let spend_address =
            bitcoin::Address::p2tr(&s, spend_pubkey, None, bitcoin::Network::Regtest);

        let blockhashes = rpc.generate_to_address(1, &funder_address)?;
        assert_eq!(blockhashes.len(), 1);

        // Get a coinbase transaction from one of the blocks we just mined
        let block = rpc.get_block(&blockhashes[0])?;
        println!("block:\n\t{:?}\n", block);

        let tx_in = &block.txdata[0];
        println!("utxo:\n\t{:#?}\n", tx_in.output);
        println!(
            "funder key: {}\n",
            funder_taproot.output_key().serialize().to_hex()
        );

        let keypair = KeyPair::new(&s, &mut rng);
        let oth_keypair = KeyPair::new(&s, &mut rng);

        let pubkeys = [
            XOnlyPublicKey::from_keypair(&s, &keypair),
            XOnlyPublicKey::from_keypair(&s, &oth_keypair),
        ];
        let timelock_keypair = KeyPair::new(&s, &mut rng);

        let mut contract = TaprootContract::with_musig_keygen(
            &s,
            keypair,
            &pubkeys,
            XOnlyPublicKey::from_keypair(&s, &timelock_keypair),
        )
        .unwrap();
        let mut oth_contract = TaprootContract::with_musig_keygen(
            &s,
            oth_keypair,
            &pubkeys,
            XOnlyPublicKey::from_keypair(&s, &timelock_keypair),
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

        assert_eq!(XOnlyPublicKey::from(_tweak_agg_a), contract.output_key()?);
        assert_eq!(XOnlyPublicKey::from(_tweak_agg_b), contract.output_key()?);
        println!(
            "contract key: {}\n",
            contract.output_key()?.serialize().to_hex()
        );

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
        let script_pubkey = Builder::new()
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .push_schnorr_key(&contract.output_key()?)
            .into_script();

        let output = [TxOut {
            value: tx_in.output[0].value - 111,
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
            sighash::SigHashCache::new(&tx)
                .taproot_signature_hash(
                    0,
                    &sighash::Prevouts::All(&tx_in.output[..1]),
                    None,
                    None,
                    sighash::SigHashType::Default,
                )?
                .into_inner()
                .as_ref(),
        )
        .unwrap();

        println!("scriptHash: {:?}\n", msg);

        // apply TapTweak to the funder keypair and sign the transaction
        funder_keypair.tweak_add_assign(&s, funder_taproot.tap_tweak().as_ref())?;

        let sig = s.sign_schnorr(&msg, &funder_keypair);

        // Verify aggregate signature is a valid Schnorr signature under the tweaked aggregate
        // public key
        assert!(s
            .verify_schnorr(&sig, &msg, &funder_taproot.output_key())
            .is_ok());

        tx.input[0].witness = [consensus::encode::serialize(sig.as_ref())].to_vec();

        assert!(tx.verify(|_s| { Some(tx_in.output[0].clone()) }).is_ok());

        let _hashes = rpc.generate_to_address(100, &spend_address)?;

        // send transaction spending funds to Musig2 contract
        let txid_out = rpc.send_raw_transaction(&tx)?;

        let _hashes = rpc.generate_to_address(1, &spend_address)?;

        let script_pubkey = Builder::new()
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .push_schnorr_key(&XOnlyPublicKey::from_keypair(&s, &timelock_keypair))
            .into_script();

        let output = [TxOut {
            value: tx.output[0].value - 111,
            script_pubkey: script_pubkey.clone(),
        }]
        .to_vec();

        let input = [TxIn {
            previous_output: OutPoint::new(txid_out, 0),
            ..Default::default()
        }]
        .to_vec();

        let mut contract_tx = Transaction {
            version: tx_in.version,
            lock_time: tx_in.lock_time,
            input,
            output,
        };

        let mut session_id = [0; 32];
        rng.fill_bytes(&mut session_id);

        let msg = Message::from_slice(
            sighash::SigHashCache::new(&contract_tx)
                .taproot_signature_hash(
                    0,
                    &sighash::Prevouts::All(&tx.output[..1]),
                    None,
                    None,
                    sighash::SigHashType::Default,
                )?
                .into_inner()
                .as_ref(),
        )
        .unwrap();
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

        let contract_sig = contract.musig_partial_sig_agg(&s, &partial_sigs)?;

        contract_tx.input[0].witness =
            [consensus::encode::serialize(contract_sig.as_ref())].to_vec();

        let _contract_txid = rpc.send_raw_transaction(&contract_tx)?;

        //---------------------
        // Script path spending
        // --------------------
        let main_sk = SecretKey::from_slice(&[
            0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2, 0x2,
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x6e, 0x6f, 0x6f, 0x6d, 0x6d, 0x6f, 0x6f, 0x6e,
        ])?;
        let keypair = KeyPair::from_secret_key(&s, main_sk);
        let oth_sk = SecretKey::from_slice(&[
            0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3, 0x3,
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x6e, 0x6f, 0x6f, 0x6d, 0x6d, 0x6f, 0x6f, 0x6e,
        ])?;
        let oth_keypair = KeyPair::from_secret_key(&s, oth_sk);

        let pubkeys = [
            XOnlyPublicKey::from_keypair(&s, &keypair),
            XOnlyPublicKey::from_keypair(&s, &oth_keypair),
        ];
        let timelock_sk = SecretKey::from_slice(&[
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
            0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x6e, 0x6f, 0x6f, 0x6d, 0x6d, 0x6f, 0x6f, 0x6e,
        ])?;
        let timelock_keypair = KeyPair::from_secret_key(&s, timelock_sk);
        let spend_keypair = KeyPair::new(&s, &mut rng);
        let timelock_key = XOnlyPublicKey::from_keypair(&s, &timelock_keypair);

        let mut contract =
            TaprootContract::with_musig_keygen(&s, keypair, &pubkeys, timelock_key.clone())
                .unwrap();
        let mut oth_contract =
            TaprootContract::with_musig_keygen(&s, oth_keypair, &pubkeys, timelock_key.clone())
                .unwrap();

        let lock_sequence = 10;
        let leaf_version = taproot::LeafVersion::default();
        contract
            .musig_create_contract(&s, lock_sequence, leaf_version)
            .unwrap();
        oth_contract
            .musig_create_contract(&s, lock_sequence, leaf_version)
            .unwrap();

        let internal_key = contract.internal_key()?;
        let contract_key = contract.output_key()?;
        let control_block = contract.control_block().unwrap();

        // Mine blocks to P2TR address
        let contract_address = contract.address(&s).unwrap();
        let blockhashes = rpc.generate_to_address(1, &contract_address)?;

        let block = rpc.get_block(&blockhashes[0])?;
        println!("block:\n\t{:?}\n", block);

        let tx_in = &block.txdata[0];
        println!("utxo:\n\t{:#?}\n", tx_in.output);
        println!("contract key: {}\n", contract_key.serialize().to_hex());
        println!("internal key: {}\n", internal_key.serialize().to_hex());
        println!("timelock key: {}\n", timelock_key.serialize().to_hex());
        println!("control block: {}\n", control_block.serialize().to_hex());
        println!(
            "merkle root: {}\n",
            contract.merkle_root().unwrap().as_ref().to_hex()
        );
        println!(
            "tap tweak: {}\n",
            contract.tap_tweak().unwrap().as_ref().to_hex()
        );
        println!(
            "leaf version: {}\n",
            contract.leaf_version().as_u8().to_hex()
        );

        // For script path spend:
        //
        // witness: <signature-timelock> <tapleaf-timelock-script> <control-block>
        // scriptPubKey: <segwit-v1> <output-key>
        //
        // TxIn {
        //   witness: vec![<signature-timelock> <tapleaf-timelock-script> <control-block>],
        //   ...
        // }
        let input = [TxIn {
            previous_output: OutPoint::new(tx_in.txid(), 0),
            sequence: lock_sequence as u32,
            ..Default::default()
        }]
        .to_vec();

        let spend_pubkey = XOnlyPublicKey::from_keypair(&s, &spend_keypair);
        let script_pubkey = Builder::new()
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .push_schnorr_key(&spend_pubkey)
            .into_script();

        let output = [TxOut {
            value: tx_in.output[0].value - 172,
            script_pubkey: script_pubkey.clone(),
        }]
        .to_vec();

        let mut tx = Transaction {
            version: tx_in.version,
            lock_time: tx_in.lock_time,
            input,
            output,
        };

        let msg = Message::from_slice(
            sighash::SigHashCache::new(&tx)
                .taproot_signature_hash(
                    0,
                    &sighash::Prevouts::All(&tx_in.output[..1]),
                    None,
                    Some(sighash::ScriptPath::new(
                        contract.script_spend()?,
                        0xffff_ffff,
                        contract.leaf_version(),
                    )),
                    sighash::SigHashType::Default,
                )?
                .into_inner()
                .as_ref(),
        )
        .unwrap();

        let sig = s.sign_schnorr(&msg, &timelock_keypair);

        // Verify TapScript signature is a valid Schnorr signature under the timelock public key
        assert!(s.verify_schnorr(&sig, &msg, &timelock_key).is_ok());

        tx.input[0].witness = [
            sig.as_ref().to_vec(),
            contract.script_spend()?[..].to_vec(),
            contract.control_block().unwrap().serialize(),
        ]
        .to_vec();

        let spend_address =
            bitcoin::Address::p2tr(&s, spend_pubkey, None, bitcoin::Network::Regtest);
        let _hashes = rpc.generate_to_address(100, &spend_address)?;

        // send transaction spending funds to Musig2 contract
        let _txid_out = rpc.send_raw_transaction(&tx)?;

        Ok(())
    }
}
