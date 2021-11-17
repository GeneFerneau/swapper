use crate::Error;
use bitcoin::{
    blockdata::{opcodes, script},
    network::constants::Network,
    secp256k1::{
        self, schnorr::Signature, KeyPair, Message, Secp256k1, Signing, Verification,
        XOnlyPublicKey,
    },
    util::{address::Address, taproot},
    Script,
};
use secp256k1_zkp::{
    MusigAggNonce, MusigPartialSignature, MusigPreSession, MusigPubNonce, MusigSecNonce,
    MusigSession,
};

pub struct TaprootContract {
    musig_pre_session: Option<MusigPreSession>,
    musig_session: Option<MusigSession>,
    spend_info: Option<taproot::TaprootSpendInfo>,
    script_spend: Option<script::Script>,
    local_keypair: KeyPair,
    timelock_key: XOnlyPublicKey,
    musig_nonce_pair: Option<(MusigSecNonce, MusigPubNonce)>,
    leaf_version: taproot::LeafVersion,
}

impl TaprootContract {
    /// Generate a shared Musig2 keypair
    ///
    /// Creates a [MusigPreSession] used to participate in Musig2 key generation.
    ///
    /// A new [MusigSession] is generated from a fresh, random nonce. Each session can
    /// only be used to sign a single message, to prevent leaking the private key through nonce
    /// reuse.
    ///
    /// `local_keypair` - local keypair for deriving share of final keypair
    /// `pubkeys` - collection of all public keys participating in the protocol
    /// `timelock_key` - public key used for timelocked backout script
    pub fn with_musig_keygen<C: secp256k1::Signing>(
        secp: &secp256k1::Secp256k1<C>,
        local_keypair: KeyPair,
        pubkeys: &[XOnlyPublicKey],
        timelock_key: XOnlyPublicKey,
    ) -> Result<Self, Error> {
        Ok(Self {
            musig_pre_session: Some(MusigPreSession::new(secp, pubkeys)?),
            musig_session: None,
            spend_info: None,
            script_spend: None,
            local_keypair,
            timelock_key,
            musig_nonce_pair: None,
            leaf_version: taproot::LeafVersion::default(),
        })
    }

    /// Tweak the aggregate public key for the [MusigPreSession]
    pub fn musig_pubkey_tweak_add<C: Signing>(
        &mut self,
        secp: &Secp256k1<C>,
        tweak: &[u8; 32],
    ) -> Result<secp256k1::PublicKey, Error> {
        self.musig_pre_session_mut()?
            .pubkey_tweak_add(secp, tweak)
            .map_err(|e| e.into())
    }

    /// Generate a Musig2 nonce pair
    ///
    /// Secret nonce is consumed during partial signing as a protection against reuse
    ///
    /// Key generation can restart with nonce generation to save computation, when signing
    /// with the same parties.
    ///
    /// `session_id` - random session identifier
    /// `local_secret_key` - local secret key used to derive the nonce pair
    /// `msg` - message to be signed
    /// `extra` - optional extra data
    pub fn musig_nonce_gen<C: Signing>(
        &mut self,
        secp: &Secp256k1<C>,
        session_id: &[u8; 32],
        msg: &Message,
        extra: Option<&[u8; 32]>,
    ) -> Result<(), Error> {
        self.musig_nonce_pair = Some(
            self.musig_pre_session()?
                .nonce_gen(secp, session_id, None, msg, extra)?,
        );
        Ok(())
    }

    /// Final stage to establish a Musig2 signing session
    ///
    /// `aggnonce` - aggregregation of all signers [MusigPubNonce]s
    /// `msg` - message to sign
    /// `adaptor` - optional adaptor public key
    pub fn musig_nonce_process<C: Signing>(
        &mut self,
        secp: &Secp256k1<C>,
        aggnonce: &MusigAggNonce,
        msg: &Message,
        adaptor: Option<&secp256k1::PublicKey>,
    ) -> Result<(), Error> {
        self.musig_session = Some(
            self.musig_pre_session()?
                .nonce_process(secp, aggnonce, msg, adaptor)?,
        );
        Ok(())
    }

    /// Create a partial signature using an established [MusigSession]
    ///
    /// Wipes the secret nonce. To start a new [MusigSession], restart with nonce generation, if
    /// signing with the same parties. Otherwise, key generation should restart completely.
    pub fn musig_partial_sign<C: Signing>(
        &mut self,
        secp: &Secp256k1<C>,
    ) -> Result<MusigPartialSignature, Error> {
        let (mut secnonce, _) = self
            .musig_nonce_pair
            .take()
            .ok_or(Error::MissingMusigNoncePair)?;
        self.musig_session()?
            .partial_sign(
                secp,
                &mut secnonce,
                &self.local_keypair,
                self.musig_pre_session()?,
            )
            .map_err(|e| e.into())
    }

    /// Verify a partial signature using an established [MusigSession]
    pub fn musig_partial_verify<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        partial_sig: &MusigPartialSignature,
        pubnonce: &MusigPubNonce,
        pubkey: &XOnlyPublicKey,
    ) -> Result<bool, Error> {
        Ok(self.musig_session()?.partial_verify(
            secp,
            partial_sig,
            pubnonce,
            pubkey,
            self.musig_pre_session()?,
        ))
    }

    /// Aggregate [MusigPartialSignature]s to create a valid Schnorr signature
    pub fn musig_partial_sig_agg<C: Signing>(
        &self,
        secp: &Secp256k1<C>,
        partial_sigs: &[MusigPartialSignature],
    ) -> Result<Signature, Error> {
        self.musig_session()?
            .partial_sig_agg(secp, partial_sigs)
            .map_err(|e| e.into())
    }

    /// Create a Taproot contract from an established [MusigSession]
    pub fn musig_create_contract<C: Signing + Verification>(
        &mut self,
        secp: &Secp256k1<C>,
        lock_sequence: i64,
        leaf_version: taproot::LeafVersion,
    ) -> Result<(), Error> {
        let script_spend = create_timelock_script(&self.timelock_key, lock_sequence);
        // not actual merkle root, since it is just for creating the unspendable script
        self.spend_info = Some(taproot::TaprootSpendInfo::with_huffman_tree(
            secp,
            *self.musig_agg_pk()?,
            [(1, script_spend.clone())],
        )?);
        self.script_spend = Some(script_spend);
        self.leaf_version = leaf_version;
        Ok(())
    }

    /// Construct a Taproot contract with provided keys, do not perform Musig2 key generation
    pub fn with_keys<C: Signing + Verification>(
        secp: &Secp256k1<C>,
        local_keypair: KeyPair,
        internal_key: XOnlyPublicKey,
        timelock_key: XOnlyPublicKey,
        lock_sequence: i64,
    ) -> Result<Self, Error> {
        let script_spend = create_timelock_script(&timelock_key, lock_sequence);
        // not actual merkle root, since it is just for creating the unspendable script
        Ok(Self {
            spend_info: Some(taproot::TaprootSpendInfo::with_huffman_tree(
                secp,
                internal_key.clone(),
                [(1, script_spend.clone())],
            )?),
            script_spend: Some(script_spend),
            local_keypair,
            timelock_key,
            musig_nonce_pair: None,
            leaf_version: taproot::LeafVersion::default(),
            musig_pre_session: None,
            musig_session: None,
        })
    }

    /// Get the parity of the Musig2 nonce
    pub fn musig_nonce_parity<C: Signing>(&mut self, secp: &Secp256k1<C>) -> Result<i32, Error> {
        self.musig_session_mut()?
            .nonce_parity(secp)
            .map_err(|e| e.into())
    }

    /// Get a const reference to the [MusigSecNonce]
    ///
    /// Returns an error if the Musig2 nonce pair is unset
    pub fn musig_sec_nonce(&self) -> Result<&MusigSecNonce, Error> {
        Ok(&self
            .musig_nonce_pair
            .as_ref()
            .ok_or(Error::MissingMusigNoncePair)?
            .0)
    }

    /// Get a mutable reference to the [MusigSecNonce]
    ///
    /// Returns an error if the Musig2 nonce pair is unset
    pub fn musig_sec_nonce_mut(&mut self) -> Result<&mut MusigSecNonce, Error> {
        Ok(&mut self
            .musig_nonce_pair
            .as_mut()
            .ok_or(Error::MissingMusigNoncePair)?
            .0)
    }

    /// Get a const reference to the [MusigPubNonce]
    ///
    /// Returns an error if the Musig2 nonce pair is unset
    pub fn musig_pub_nonce(&self) -> Result<&MusigPubNonce, Error> {
        Ok(&self
            .musig_nonce_pair
            .as_ref()
            .ok_or(Error::MissingMusigNoncePair)?
            .1)
    }

    /// Get a const reference to the [MusigPreSession]
    ///
    /// Returns an error if the Musig2 pre-session is unset
    pub fn musig_pre_session(&self) -> Result<&MusigPreSession, Error> {
        self.musig_pre_session
            .as_ref()
            .ok_or(Error::MissingMusigPreSession)
    }

    /// Get a mutable reference to the [MusigPreSession]
    ///
    /// Returns an error if the Musig2 pre-session is unset
    pub fn musig_pre_session_mut(&mut self) -> Result<&mut MusigPreSession, Error> {
        self.musig_pre_session
            .as_mut()
            .ok_or(Error::MissingMusigPreSession)
    }

    /// Get a const reference to the [MusigSession]
    ///
    /// Returns an error if the Musig2 session is unset
    pub fn musig_session(&self) -> Result<&MusigSession, Error> {
        self.musig_session
            .as_ref()
            .ok_or(Error::MissingMusigSession)
    }

    /// Get a const reference to the [MusigSession]
    ///
    /// Returns an error if the Musig2 session is unset
    pub fn musig_session_mut(&mut self) -> Result<&mut MusigSession, Error> {
        self.musig_session
            .as_mut()
            .ok_or(Error::MissingMusigSession)
    }

    /// Aggregate public key for a [MusigPreSession]
    ///
    /// Used as the `internal_key` for the Taproot key path spend
    ///
    /// Returns error if the Musig2 pre-session is unset
    pub fn musig_agg_pk(&self) -> Result<&XOnlyPublicKey, Error> {
        Ok(self.musig_pre_session()?.agg_pk())
    }

    /// Get a const reference to the timelock public key
    pub fn timelock_key(&self) -> &XOnlyPublicKey {
        &self.timelock_key
    }

    /// Get the control block for the Taproot spend script
    pub fn control_block(&self) -> Option<taproot::ControlBlock> {
        match (self.spend_info.as_ref(), self.script_spend.as_ref()) {
            (Some(s), Some(sc)) => s.control_block(&(sc.clone(), self.leaf_version)),
            _ => None,
        }
    }

    pub fn merkle_root(&self) -> Option<taproot::TapBranchHash> {
        if let Some(s) = self.spend_info.as_ref() {
            s.merkle_root()
        } else {
            None
        }
    }

    pub fn tap_tweak(&self) -> Option<taproot::TapTweakHash> {
        if let Some(s) = self.spend_info.as_ref() {
            Some(s.tap_tweak())
        } else {
            None
        }
    }

    pub fn leaf_version(&self) -> taproot::LeafVersion {
        self.leaf_version
    }

    fn network() -> Network {
        if cfg!(feature = "regtest") {
            Network::Regtest
        } else if cfg!(feature = "signet") {
            Network::Signet
        } else {
            Network::Bitcoin
        }
    }

    /// Get the P2TR address for this contract
    pub fn address<C: Verification>(&self, secp: &Secp256k1<C>) -> Option<Address> {
        if let Some(c) = self.spend_info.as_ref() {
            Some(Address::p2tr(
                secp,
                c.internal_key(),
                c.merkle_root(),
                Self::network(),
            ))
        } else {
            None
        }
    }

    pub fn internal_key(&self) -> Result<XOnlyPublicKey, Error> {
        Ok(self
            .spend_info
            .as_ref()
            .ok_or(Error::MissingSpendInfo)?
            .internal_key())
    }

    pub fn output_key(&self) -> Result<XOnlyPublicKey, Error> {
        Ok(self
            .spend_info
            .as_ref()
            .ok_or(Error::MissingSpendInfo)?
            .output_key())
    }

    pub fn script_spend(&self) -> Result<&Script, Error> {
        self.script_spend.as_ref().ok_or(Error::MissingScriptSpend)
    }
}

// create TapScript for timelock backout spend
fn create_timelock_script(timelock_key: &XOnlyPublicKey, lock_sequence: i64) -> script::Script {
    // comments: witness script stack after next operation
    script::Builder::new()
        // sig <lock_seq>
        .push_int(lock_sequence)
        // sig <lock_seq>
        .push_opcode(opcodes::all::OP_CSV)
        // sig
        .push_opcode(opcodes::all::OP_DROP)
        // sig <timelock_key>
        .push_schnorr_key(timelock_key)
        // [true|false]
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}
