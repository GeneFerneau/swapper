use bitcoin::secp256k1::Error as Secp256k1Error;
use bitcoin::util::{sighash::Error as SigHashError, taproot::TaprootBuilderError};
use mpecdsa::state_machine::keygen::Error as MpEcdsaKeygenError;
use mpecdsa::state_machine::sign::{
    Error as MpEcdsaSignError, SignError as MpEcdsaSignManualError,
};
use mpecdsa::Error as MpEcdsaError;
use mpecdsa::ErrorType as MpEcdsaErrorType;
use secp256k1_zkp::Error as Secp256k1ZkpError;

#[cfg(any(feature = "regtest", feature = "signet"))]
use bitcoincore_rpc::Error as RpcError;

#[derive(Debug)]
pub enum Error {
    MpEcdsa(MpEcdsaError),
    MpEcdsaType(MpEcdsaErrorType),
    TaprootBuilder(TaprootBuilderError),
    MpEcdsaKeygen(MpEcdsaKeygenError),
    MpEcdsaSign(MpEcdsaSignError),
    MpEcdsaSignManual(MpEcdsaSignManualError),
    #[cfg(any(feature = "regtest", feature = "signet"))]
    Rpc(RpcError),
    Secp256k1(Secp256k1Error),
    Secp256k1Zkp(Secp256k1ZkpError),
    SigHash(SigHashError),
    IncompleteEcdsa2pKeygen,
    IncompleteEcdsa2pOfflineSigning,
    InvalidEcdsa2pIndex,
    MissingOfflineSignState,
    MissingSignManualState,
    MissingMusigPreSession,
    MissingMusigSession,
    MissingMusigNoncePair,
    MissingScriptSpend,
    MissingSpendInfo,
}

impl From<MpEcdsaError> for Error {
    fn from(e: MpEcdsaError) -> Self {
        Self::MpEcdsa(e)
    }
}

impl From<MpEcdsaErrorType> for Error {
    fn from(e: MpEcdsaErrorType) -> Self {
        Self::MpEcdsaType(e)
    }
}

impl From<MpEcdsaKeygenError> for Error {
    fn from(e: MpEcdsaKeygenError) -> Self {
        Self::MpEcdsaKeygen(e)
    }
}

impl From<MpEcdsaSignError> for Error {
    fn from(e: MpEcdsaSignError) -> Self {
        Self::MpEcdsaSign(e)
    }
}

impl From<MpEcdsaSignManualError> for Error {
    fn from(e: MpEcdsaSignManualError) -> Self {
        Self::MpEcdsaSignManual(e)
    }
}

#[cfg(any(feature = "regtest", feature = "signet"))]
impl From<RpcError> for Error {
    fn from(e: RpcError) -> Self {
        Self::Rpc(e)
    }
}

impl From<Secp256k1Error> for Error {
    fn from(e: Secp256k1Error) -> Self {
        Self::Secp256k1(e)
    }
}

impl From<SigHashError> for Error {
    fn from(e: SigHashError) -> Self {
        Self::SigHash(e)
    }
}

impl From<Secp256k1ZkpError> for Error {
    fn from(e: Secp256k1ZkpError) -> Self {
        Self::Secp256k1Zkp(e)
    }
}

impl From<TaprootBuilderError> for Error {
    fn from(e: TaprootBuilderError) -> Self {
        Self::TaprootBuilder(e)
    }
}
