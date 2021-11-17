use alloc::vec::Vec;

use bitcoin::{
    blockdata::{opcodes, script},
    secp256k1, PublicKey,
};
use curv::{arithmetic::Converter, BigInt};
use log::debug;
use mpecdsa::{
    party_i::SignatureRecid,
    state_machine::{keygen, sign},
};
use round_based::{IsCritical, Msg, StateMachine};

use crate::Error;

pub const N: usize = 2;
pub const M: usize = N - 1;
pub const T: usize = N - 1;

pub struct Ecdsa2pContract {
    keygen_state: keygen::Keygen,
    offline_sign_state: Option<sign::OfflineStage>,
}

/// Threshold t1-n2 ECDSA2p contract
impl Ecdsa2pContract {
    /// Start key generation rounds to construct verifiable distributed key shares
    ///
    /// i: local one-based index in the set of parties
    pub fn with_keygen(i: u16) -> Result<Self, Error> {
        Ok(Self {
            keygen_state: keygen::Keygen::new(i, T as u16, N as u16)?,
            offline_sign_state: None,
        })
    }

    /// Handle key generation round message
    ///
    /// Each round will have `N - 1` other messages
    pub fn keygen_handle_incoming(
        &mut self,
        msgs: &[Msg<keygen::ProtocolMessage>],
    ) -> Result<(), Error> {
        for msg in msgs {
            if Some(self.keygen_state.party_ind()) != msg.receiver
                && (msg.receiver.is_some() || msg.sender == self.keygen_state.party_ind())
            {
                continue;
            }
            debug!(
                "Party {} got message from={}, broadcast={}: {:?}",
                self.keygen_state.party_ind(),
                msg.sender,
                msg.receiver.is_none(),
                msg.body,
            );
            debug!("  - before: {:?}", self.keygen_state);
            match self.keygen_state.handle_incoming(msg.clone()) {
                Ok(()) => (),
                Err(err) if err.is_critical() => return Err(err.into()),
                Err(err) => {
                    debug!("Non-critical error encountered: {:?}", err);
                }
            }
            debug!("  - after : {:?}", self.keygen_state);
            debug!("");
        }
        Ok(())
    }

    /// Append outgoing messages to the supplied buffer from the local queue
    pub fn keygen_send_outgoing(
        &mut self,
        msgs: &mut Vec<Msg<keygen::ProtocolMessage>>,
    ) -> Result<(), Error> {
        if !self.keygen_state.message_queue().is_empty() {
            debug!(
                "Party {} sends {} message(s)",
                self.keygen_state.party_ind(),
                self.keygen_state.message_queue().len()
            );
            debug!("");

            msgs.append(self.keygen_state.message_queue());
        }
        Ok(())
    }

    /// Proceed to the next key generation round, if the state machine wants to proceed
    pub fn keygen_proceed_if_needed(&mut self) -> Result<(), Error> {
        if !self.keygen_state.wants_to_proceed() {
            return Ok(());
        }

        debug!("Party {} wants to proceed", self.keygen_state.party_ind());
        debug!("  - before: {:?}", self.keygen_state);

        match self.keygen_state.proceed() {
            Ok(()) => (),
            Err(err) if err.is_critical() => return Err(err.into()),
            Err(err) => {
                debug!("Non-critical error encountered: {:?}", err);
            }
        }

        debug!("  - after: {:?}", self.keygen_state);

        Ok(())
    }

    /// Whether the key generation protocol is finished
    pub fn keygen_is_finished(&self) -> bool {
        self.keygen_state.is_finished()
    }

    /// Start offline signing rounds after a successful key generation
    pub fn start_offline_sign(&mut self) -> Result<(), Error> {
        let party_ind = self.keygen_state.party_ind();
        debug_assert_eq!(
            self.keygen_state.parties() as usize,
            N,
            "invalid number of ECDSA2p parties"
        );

        let mut oth_parties = [0u16; M];
        for (i, p) in oth_parties
            .iter_mut()
            .zip((0..self.keygen_state.parties()).filter(|&i| i != party_ind))
        {
            *i = p;
        }
        self.offline_sign_state = Some(sign::OfflineStage::new(
            party_ind,
            &oth_parties,
            self.local_key()?,
        )?);
        Ok(())
    }

    /// Handle key generation round message
    ///
    /// Each round will have `N - 1` other messages
    pub fn offline_sign_handle_incoming(
        &mut self,
        msgs: &[Msg<sign::OfflineProtocolMessage>],
    ) -> Result<(), Error> {
        let offline_state = self.offline_sign_state()?;
        for msg in msgs {
            if Some(offline_state.party_ind()) != msg.receiver
                && (msg.receiver.is_some() || msg.sender == offline_state.party_ind())
            {
                continue;
            }
            debug!(
                "Party {} got message from={}, broadcast={}: {:?}",
                offline_state.party_ind(),
                msg.sender,
                msg.receiver.is_none(),
                msg.body,
            );
            debug!("  - before: {:?}", offline_state);
            match offline_state.handle_incoming(msg.clone()) {
                Ok(()) => (),
                Err(err) if err.is_critical() => return Err(err.into()),
                Err(err) => {
                    debug!("Non-critical error encountered: {:?}", err);
                }
            }
            debug!("  - after : {:?}", offline_state);
            debug!("");
        }
        Ok(())
    }

    /// Add offline signing protocol messages to the provided buffer from the message queue
    pub fn offline_sign_send_outgoing(
        &mut self,
        msgs: &mut Vec<Msg<sign::OfflineProtocolMessage>>,
    ) -> Result<(), Error> {
        let offline_state = self.offline_sign_state()?;
        if !offline_state.message_queue().is_empty() {
            debug!(
                "Party {} sends {} message(s)",
                offline_state.party_ind(),
                offline_state.message_queue().len()
            );
            debug!("");

            msgs.append(offline_state.message_queue());
        }
        Ok(())
    }

    /// Proceed to the next offline signing state, if the state machine wants to proceed
    pub fn offline_sign_proceed_if_needed(&mut self) -> Result<(), Error> {
        let offline_state = self.offline_sign_state()?;
        if !offline_state.wants_to_proceed() {
            return Ok(());
        }

        debug!("Party {} wants to proceed", offline_state.party_ind());
        debug!("  - before: {:?}", offline_state);

        match offline_state.proceed() {
            Ok(()) => (),
            Err(err) if err.is_critical() => return Err(err.into()),
            Err(err) => {
                debug!("Non-critical error encountered: {:?}", err);
            }
        }

        debug!("  - after: {:?}", offline_state);

        Ok(())
    }

    /// Whether the offline signing protocol is finished
    pub fn offline_sign_is_finished(&self) -> bool {
        if let Some(o) = self.offline_sign_state.as_ref() {
            o.is_finished()
        } else {
            false
        }
    }

    fn offline_sign_state(&mut self) -> Result<&mut sign::OfflineStage, Error> {
        self.offline_sign_state
            .as_mut()
            .ok_or(Error::MissingOfflineSignState)
    }

    /// Get the local keyshare created during key generation
    pub fn local_key(&mut self) -> Result<keygen::LocalKey, Error> {
        match self.keygen_state.pick_output() {
            Some(Ok(k)) => Ok(k),
            Some(Err(e)) => Err(e.into()),
            None => Err(Error::IncompleteEcdsa2pKeygen),
        }
    }

    /// Get the shared public key aggregated from all the keyshares
    pub fn shared_key(&mut self) -> Result<secp256k1::PublicKey, Error> {
        secp256k1::PublicKey::from_slice(self.local_key()?.public_key().to_bytes(true).as_ref())
            .map_err(|e| e.into())
    }

    /// Create a partial signature using the local share of the aggregate ECSDA2p key
    pub fn partial_sign(
        &mut self,
        msg: &[u8],
    ) -> Result<(sign::SignManual, sign::PartialSignature), Error> {
        let sign_completed = match self.offline_sign_state()?.pick_output() {
            Some(Ok(c)) => c,
            Some(Err(e)) => return Err(e.into()),
            None => return Err(Error::IncompleteEcdsa2pOfflineSigning),
        };

        sign::SignManual::new(BigInt::from_bytes(msg), sign_completed).map_err(|e| e.into())
    }

    /// Create script with two outputs:
    ///
    /// - spendable with threshold signers aggregated signatures
    /// - spendable with a timelock public key after relative timelock expires
    pub fn create_script(
        &mut self,
        timelock_key: &secp256k1::PublicKey,
        lock_sequence: i64,
    ) -> Result<script::Script, Error> {
        let shared_key = PublicKey::new(self.shared_key()?);
        // comments: script stack after next operation
        Ok(script::Builder::new()
            // sig pubkey <shared_key>
            .push_key(&shared_key)
            // sig [true|false]
            .push_opcode(opcodes::all::OP_EQUAL)
            // sig
            .push_opcode(opcodes::all::OP_IF)
            // sig <shared_key>
            .push_key(&shared_key)
            // sig
            .push_opcode(opcodes::all::OP_ELSE)
            // sig <lock_sequence>
            .push_int(lock_sequence)
            // sig <lock_sequence>
            .push_opcode(opcodes::all::OP_CSV)
            // sig
            .push_opcode(opcodes::all::OP_DROP)
            // sig <timelock_key>
            .push_key(&PublicKey::new(timelock_key.clone()))
            // sig [<shared_key>|<timelock_key>]
            .push_opcode(opcodes::all::OP_ENDIF)
            // [true|false]
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script())
    }

    /// Complete the aggregate ECDSA signature from the partial signatures
    pub fn complete_multisignature(
        state: sign::SignManual,
        part_sigs: &[sign::PartialSignature],
    ) -> Result<SignatureRecid, Error> {
        state.complete(part_sigs).map_err(|e| e.into())
    }
}
