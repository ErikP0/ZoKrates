mod bn128;

use zokrates_field::field::FieldPrime;

pub use self::bn128::G16;
#[cfg(feature = "libsnark")]
pub use self::bn128::GM17;
#[cfg(feature = "libsnark")]
pub use self::bn128::PGHR13;

use crate::ir;
use serde::{Serialize, de::DeserializeOwned};

// We only need to serialize this struct, there is no need for deserialization as keys are
// used separetely in other use cases
#[derive(Serialize)]
pub struct SetupKeypair<PK: ProvingKey, VK: VerifyingKey> {
    pub vk: VK,
    pub pk: PK,
}

#[derive(Serialize)]
pub struct ProofWithInputs<P: Proof> {
    pub proof: P,
    pub inputs: Vec<P::Input>
}

impl<PK: ProvingKey, VK: VerifyingKey> SetupKeypair<PK,VK> {
    pub fn from(vk: VK, pk: PK) -> Self {
        SetupKeypair { vk, pk }
    }

    pub fn vk(&self) -> String {
        serde_json::to_string(&self.vk).unwrap()
    }

    pub fn pk(&self) -> Vec<u8> {
        self.pk.clone().into()
    }
}

pub trait Proof: Clone + Serialize + DeserializeOwned {
    type Input: Clone + PartialEq + Serialize;
}
pub trait VerifyingKey: Clone + PartialEq + Serialize + DeserializeOwned { }
pub trait ProvingKey: Into<Vec<u8>> + Clone + PartialEq {
    fn from_bytes(v: Vec<u8>) -> Result<Self, String>;
}

pub trait ProofSystem {
    type Proof: Proof;
    type VerifyingKey: VerifyingKey;
    type ProvingKey: ProvingKey;

    fn new_proving_key(&self, bytes: Vec<u8>) -> Result<Self::ProvingKey, String> {
        Self::ProvingKey::from_bytes(bytes)
    }

    fn new_verifying_key(&self, str_repr: &str) -> Result<Self::VerifyingKey, String> {
        serde_json::from_str(str_repr).map_err(|err| format!("Couldn't parse verifying key {}", err))
    }

    fn setup(&self, program: ir::Prog<FieldPrime>) -> SetupKeypair<Self::ProvingKey, Self::VerifyingKey>;

    fn generate_proof(
        &self,
        program: ir::Prog<FieldPrime>,
        witness: ir::Witness<FieldPrime>,
        proving_key: &Self::ProvingKey,
    ) -> ProofWithInputs<Self::Proof>;

    fn verify_proof(&self, proof: &Self::Proof, vk: &Self::VerifyingKey, public_inputs: &[<Self::Proof as Proof>::Input]) -> bool;

    fn export_solidity_verifier(&self, vk: &Self::VerifyingKey, is_abiv2: bool) -> String;
}
