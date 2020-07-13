use crate::ir;
use crate::proof_system::bn128::utils::bellman::Computation;
use crate::proof_system::bn128::utils::solidity::{
    SOLIDITY_G2_ADDITION_LIB, SOLIDITY_PAIRING_LIB, SOLIDITY_PAIRING_LIB_V2,
};
use crate::proof_system::{ProofSystem, SetupKeypair};
use regex::Regex;

use std::io::{Cursor, Read};
use zokrates_field::field::FieldPrime;
use proof_system;
use pairing::bn256::Bn256;
use pairing::CurveAffine; // for G1Affine::one(), G2Affine::one()
use proof_system::ProofWithInputs;
use itertools::Itertools;
use proof_system::bn128::g16::serialize::{SerializableG1, SerializableG2, SerializableFr};

const G16_WARNING: &str = "WARNING: You are using the G16 scheme which is subject to malleability. See zokrates.github.io/reference/proving_schemes.html#g16-malleability for implications.";

pub struct G16 {}

impl G16 {
    pub fn new() -> G16 {
        G16 {}
    }
}

impl ProofSystem for G16 {
    type Proof = G16Proof;
    type ProvingKey = G16ProvingKey;
    type VerifyingKey = G16VerifyingKey;

    fn setup(&self, program: ir::Prog<FieldPrime>) -> SetupKeypair<G16ProvingKey, G16VerifyingKey> {
        #[cfg(not(target_arch = "wasm32"))]
        std::env::set_var("BELLMAN_VERBOSE", "0");
        println!("{}", G16_WARNING);

        let parameters = Computation::without_witness(program).setup();
        SetupKeypair::from(parameters.vk.clone().into(), G16ProvingKey(parameters))
    }

    fn generate_proof(
        &self,
        program: ir::Prog<FieldPrime>,
        witness: ir::Witness<FieldPrime>,
        proving_key: &G16ProvingKey,
    ) -> ProofWithInputs<G16Proof> {
        #[cfg(not(target_arch = "wasm32"))]
        std::env::set_var("BELLMAN_VERBOSE", "0");

        println!("{}", G16_WARNING);

        let computation = Computation::with_witness(program, witness);

        let proof = computation.clone().prove(&proving_key.0);
        ProofWithInputs {
            proof: proof.into(),
            inputs: computation.public_inputs_values().into_iter().map(Into::into).collect(),
        }
    }

    fn verify_proof(&self, proof: &G16Proof, vk: &G16VerifyingKey, public_inputs: &[SerializableFr]) -> bool {
        let pvk = bellman_ce::groth16::prepare_verifying_key(&vk.clone().into());
        let inputs: Vec<pairing_ce::bn256::Fr> = public_inputs.iter().cloned().map(Into::into).collect();
        bellman_ce::groth16::verify_proof(&pvk, &proof.clone().into(), &inputs).unwrap()
    }

    fn export_solidity_verifier(&self, vk: &G16VerifyingKey, is_abiv2: bool) -> String {
        let (mut template_text, solidity_pairing_lib) = if is_abiv2 {
            (
                String::from(CONTRACT_TEMPLATE_V2),
                String::from(SOLIDITY_PAIRING_LIB_V2),
            )
        } else {
            (
                String::from(CONTRACT_TEMPLATE),
                String::from(SOLIDITY_PAIRING_LIB),
            )
        };

        fn g1_constructor(g1: &SerializableG1) -> String {
            let (x,y) = g1.coordinates_to_hex();
            format!("uint256(0x{x}), uint256(0x{y})", x=x, y=y)
        }

        fn g2_constructor(g2: &SerializableG2) -> String {
            let ((xc0,xc1), (yc0, yc1)) = g2.coordinates_to_hex();
            format!("[uint256(0x{xc0}), uint256(0x{xc1})], [uint256(0x{yc0}), uint256(0x{yc1})]", xc0=xc0, xc1=xc1, yc0=yc0, yc1=yc1)
        }

        //replace things in template
        let vk_regex_a = Regex::new(r#"<%vk_a%>"#).unwrap();
        template_text = vk_regex_a.replace(&template_text, g1_constructor(&vk.alpha_g1).as_str())
            .into_owned();
        let vk_regex_b = Regex::new(r#"<%vk_b%>"#).unwrap();
        template_text = vk_regex_b.replace(&template_text, g2_constructor(&vk.beta_g2).as_str()).into_owned();
        let vk_regex_gamma = Regex::new(r#"<%vk_gamma%>"#).unwrap();
        template_text = vk_regex_gamma.replace(&template_text, g2_constructor(&vk.gamma_g2).as_str()).into_owned();
        let vk_regex_delta = Regex::new(r#"<%vk_delta%>"#).unwrap();
        template_text = vk_regex_delta.replace(&template_text, g2_constructor(&vk.delta_g2).as_str()).into_owned();

        let vk_gamma_abc_len_regex = Regex::new(r#"(<%vk_gamma_abc_length%>)"#).unwrap();
        template_text = vk_gamma_abc_len_regex.replace(&template_text, format!("{}", vk.gamma_abc.len()).as_str())
            .into_owned();

        let vk_gamma_abc_repeat_regex = Regex::new(r#"(<%vk_gamma_abc_pts%>)"#).unwrap();
        let vk_gamma_abc_replacement = vk.gamma_abc.iter()
            .enumerate()
            .map(|(i,gamma_abc)| format!("        vk.gamma_abc[{i}] = Pairing.G1Point({g1});", i=i, g1=g1_constructor(gamma_abc)))
            .join("\n");
        template_text = vk_gamma_abc_repeat_regex.replace(&template_text, vk_gamma_abc_replacement.as_str())
            .into_owned();

        let vk_input_len_regex = Regex::new(r#"(<%vk_input_length%>)"#).unwrap();
        template_text = vk_input_len_regex.replace(&template_text, format!("{}", vk.gamma_abc.len()-1).as_str())
            .into_owned();

        format!(
            "{}{}{}",
            SOLIDITY_G2_ADDITION_LIB, solidity_pairing_lib, template_text
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct G16Proof {
    a: SerializableG1,
    b: SerializableG2,
    c: SerializableG1,
}

impl From<bellman::groth16::Proof<Bn256>> for G16Proof {
    fn from(proof: bellman::groth16::Proof<Bn256>) -> Self {
        G16Proof {
            a: proof.a.into(),
            b: proof.b.into(),
            c: proof.c.into(),
        }
    }
}

impl Into<bellman::groth16::Proof<Bn256>> for G16Proof {
    fn into(self) -> bellman::groth16::Proof<Bn256> {
        bellman::groth16::Proof {
            a: self.a.into(),
            b: self.b.into(),
            c: self.c.into(),
        }
    }
}

impl proof_system::Proof for G16Proof {
    type Input = SerializableFr;
}

#[derive(Clone, PartialEq)]
pub struct G16ProvingKey(bellman::groth16::Parameters<Bn256>);

impl proof_system::ProvingKey for G16ProvingKey {
    fn from_bytes(v: Vec<u8>) -> Result<Self,String> {
        bellman::groth16::Parameters::read(v.as_slice(), true)
            .map(|params| G16ProvingKey(params))
            .map_err(|err| format!("Invalid G16 proving key: {}", err))
    }
}

impl Into<Vec<u8>> for G16ProvingKey {
    fn into(self) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());

        self.0.write(&mut cursor).unwrap();
        cursor.set_position(0);

        let mut pk: Vec<u8> = Vec::new();
        cursor
            .read_to_end(&mut pk)
            .expect("Could not read cursor buffer");
        pk
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct G16VerifyingKey {
    alpha_g1: SerializableG1,
    beta_g2: SerializableG2,
    gamma_g2: SerializableG2,
    delta_g2: SerializableG2,
    gamma_abc: Vec<SerializableG1>,
}

impl From<bellman_ce::groth16::VerifyingKey<Bn256>> for G16VerifyingKey {
    fn from(vk: bellman_ce::groth16::VerifyingKey<Bn256>) -> Self {
        G16VerifyingKey {
            alpha_g1: vk.alpha_g1.into(),
            beta_g2: vk.beta_g2.into(),
            gamma_g2: vk.gamma_g2.into(),
            delta_g2: vk.delta_g2.into(),
            gamma_abc: vk.ic.into_iter().map(|g1| g1.into()).collect()
        }
    }
}

impl Into<bellman_ce::groth16::VerifyingKey<Bn256>> for G16VerifyingKey {
    fn into(self) -> bellman_ce::groth16::VerifyingKey<Bn256> {
        bellman_ce::groth16::VerifyingKey::<Bn256> {
            alpha_g1: self.alpha_g1.into(),
            beta_g1: pairing_ce::bn256::G1Affine::one(), // not used for verification process
            beta_g2: self.beta_g2.into(),
            gamma_g2: self.gamma_g2.into(),
            delta_g1: pairing_ce::bn256::G1Affine::one(), // not used for verification process
            delta_g2: self.delta_g2.into(),
            ic: self.gamma_abc.into_iter().map(|g1| g1.into()).collect(),
        }
    }
}

impl proof_system::VerifyingKey for G16VerifyingKey { }

mod serialize {
    use serde::{Serialize, Deserialize, Serializer, Deserializer};
    use std::fmt;
    use serde::de::{SeqAccess, Visitor, Error as SerdeError};
    use pairing::bn256::{Fr, G1Affine, G2Affine, Fq, Fq2};
    use serde::ser::SerializeTuple;
    use pairing::CurveAffine;

    #[derive(Clone, Debug, PartialEq)]
    pub struct SerializableFr(Fr);

    impl Serialize for SerializableFr {
        fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
            S: Serializer {
            serializer.serialize_str(&pairing_ce::to_hex(&self.0))
        }
    }

    impl From<Fr> for SerializableFr {
        fn from(fr: Fr) -> Self {
            SerializableFr(fr)
        }
    }

    impl Into<Fr> for SerializableFr {
        fn into(self) -> Fr {
            self.0
        }
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct SerializableG1(G1Affine);

    impl SerializableG1 {
        /// returns x and y coordinate in affine form without 0x prefix
        pub(crate) fn coordinates_to_hex(&self) -> (String, String) {
            let (x,y) = self.0.as_xy();
            (pairing_ce::to_hex(x), pairing_ce::to_hex(y))
        }
    }

    impl From<G1Affine> for SerializableG1 {
        fn from(g1: G1Affine) -> Self {
            SerializableG1(g1)
        }
    }

    impl Into<G1Affine> for SerializableG1 {
        fn into(self) -> G1Affine {
            self.0
        }
    }

    impl Serialize for SerializableG1 {
        fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
            S: Serializer {
            let mut tuple = serializer.serialize_tuple(2)?;
            let (x_str, y_str) = self.coordinates_to_hex();
            tuple.serialize_element(&x_str)?;
            tuple.serialize_element(&y_str)?;
            tuple.end()
        }
    }

    impl<'de> Deserialize<'de> for SerializableG1 {

        fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
            D: Deserializer<'de> {
            struct G1TupleReprVisitor;
            impl<'de> Visitor<'de> for G1TupleReprVisitor {
                type Value = SerializableG1;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a tuple of 2 fq field elements")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, <A as SeqAccess<'de>>::Error> where
                    A: SeqAccess<'de>, {
                    let x_str: String = seq.next_element()?
                        .ok_or_else(|| SerdeError::invalid_length(0, &self))?;
                    let y_str: String = seq.next_element()?
                        .ok_or_else(|| SerdeError::invalid_length(1, &self))?;
                    let x: Fq = pairing_ce::from_hex(&x_str).map_err(|err| SerdeError::custom(format!("Could not decode Fq element: {}", err)))?;
                    let y: Fq = pairing_ce::from_hex(&y_str).map_err(|err| SerdeError::custom(format!("Could not decode Fq element: {}", err)))?;
                    Ok(SerializableG1(
                        pairing_ce::bn256::G1Affine::from_xy_checked(x,y).map_err(|err| SerdeError::custom(format!("Provided Fq elements don't form a valid G1 element: {}", err)))?
                    ))
                }
            }

            deserializer.deserialize_tuple(2, G1TupleReprVisitor)
        }
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct SerializableG2(G2Affine);

    impl SerializableG2 {
        pub(crate) fn coordinates_to_hex(&self) -> ((String, String), (String, String)) {
            let (x,y) = self.0.as_xy();
            ((pairing_ce::to_hex(&x.c0), pairing_ce::to_hex(&x.c1)), (pairing_ce::to_hex(&y.c0), pairing_ce::to_hex(&y.c1)))
        }
    }

    impl From<G2Affine> for SerializableG2 {
        fn from(g2: G2Affine) -> Self {
            SerializableG2(g2)
        }
    }

    impl Into<G2Affine> for SerializableG2 {
        fn into(self) -> G2Affine {
            self.0
        }
    }

    impl Serialize for SerializableG2 {
        fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error> where
            S: Serializer {

            let mut tuple = serializer.serialize_tuple(2)?;
            let (x, y) = self.coordinates_to_hex();
            tuple.serialize_element(&x)?;
            tuple.serialize_element(&y)?;
            tuple.end()
        }
    }

    impl<'de> Deserialize<'de> for SerializableG2 {
        fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
            D: Deserializer<'de> {
            struct G2TupleReprVisitor;

            impl<'de> Visitor<'de> for G2TupleReprVisitor {
                type Value = SerializableG2;

                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a tuple of 2 fq2 elements")
                }

                fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, <A as SeqAccess<'de>>::Error> where
                    A: SeqAccess<'de>, {
                    let (xc0_str, xc1_str) = seq.next_element::<(String,String)>()?
                        .ok_or_else(|| SerdeError::invalid_length(0, &self))?;
                    let (yc0_str, yc1_str) = seq.next_element::<(String,String)>()?
                        .ok_or_else(|| SerdeError::invalid_length(1, &self))?;
                    let xc0: Fq = pairing_ce::from_hex(&xc0_str).map_err(|err| SerdeError::custom(format!("Could not decode Fq element: {}", err)))?;
                    let xc1: Fq = pairing_ce::from_hex(&xc1_str).map_err(|err| SerdeError::custom(format!("Could not decode Fq element: {}", err)))?;
                    let yc0: Fq = pairing_ce::from_hex(&yc0_str).map_err(|err| SerdeError::custom(format!("Could not decode Fq element: {}", err)))?;
                    let yc1: Fq = pairing_ce::from_hex(&yc1_str).map_err(|err| SerdeError::custom(format!("Could not decode Fq element: {}", err)))?;
                    Ok(SerializableG2(
                        G2Affine::from_xy_checked(
                            Fq2 { c0: xc0, c1: xc1},
                            Fq2 { c0: yc0, c1: yc1},
                        )
                            .map_err(|err| SerdeError::custom(format!("Provided Fq2 elements don't form a valid G2 element: {}", err)))?
                    ))
                }
            }

            deserializer.deserialize_tuple(2, G2TupleReprVisitor)
        }
    }
}

const CONTRACT_TEMPLATE_V2: &str = r#"
contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.a = Pairing.G1Point(<%vk_a%>);
        vk.b = Pairing.G2Point(<%vk_b%>);
        vk.gamma = Pairing.G2Point(<%vk_gamma%>);
        vk.delta = Pairing.G2Point(<%vk_delta%>);
        vk.gamma_abc = new Pairing.G1Point[](<%vk_gamma_abc_length%>);
        <%vk_gamma_abc_pts%>
    }
    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.a), vk.b)) return 1;
        return 0;
    }
    event Verified(string s);
    function verifyTx(
            Proof memory proof,
            uint[<%vk_input_length%>] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](input.length);
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            emit Verified("Transaction successfully verified.");
            return true;
        } else {
            return false;
        }
    }
}
"#;

const CONTRACT_TEMPLATE: &str = r#"
contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.a = Pairing.G1Point(<%vk_a%>);
        vk.b = Pairing.G2Point(<%vk_b%>);
        vk.gamma = Pairing.G2Point(<%vk_gamma%>);
        vk.delta = Pairing.G2Point(<%vk_delta%>);
        vk.gamma_abc = new Pairing.G1Point[](<%vk_gamma_abc_length%>);
        <%vk_gamma_abc_pts%>
    }
    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.a), vk.b)) return 1;
        return 0;
    }
    event Verified(string s);
    function verifyTx(
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[<%vk_input_length%>] memory input
        ) public returns (bool r) {
        Proof memory proof;
        proof.a = Pairing.G1Point(a[0], a[1]);
        proof.b = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.c = Pairing.G1Point(c[0], c[1]);
        uint[] memory inputValues = new uint[](input.length);
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            emit Verified("Transaction successfully verified.");
            return true;
        } else {
            return false;
        }
    }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flat_absy::FlatVariable;
    use crate::ir::*;

    fn program_setup() -> Computation<FieldPrime> {
        let program: Prog<FieldPrime> = Prog {
            main: Function {
                id: String::from("main"),
                arguments: vec![FlatVariable::new(0)],
                returns: vec![FlatVariable::public(0)],
                statements: vec![Statement::Constraint(
                    FlatVariable::new(0).into(),
                    FlatVariable::public(0).into(),
                )],
            },
            private: vec![false],
        };

        let witness = program
            .clone()
            .execute(&vec![FieldPrime::from(42)])
            .unwrap();
        Computation::with_witness(program, witness)
    }

    mod serialize {
        use super::*;
        use serde_json::Value;

        #[test]
        fn serialize_verifying_key() {
            let computation = program_setup();

            let params = computation.clone().setup();
            let vk_before: G16VerifyingKey = params.vk.clone().into();
            let vk_serialized = serde_json::to_string(&vk_before).unwrap();
            let vk_after = serde_json::from_str(&vk_serialized).unwrap();

            assert_eq!(vk_before, vk_after);
        }

        #[test]
        fn serialize_proof() {
            let computation = program_setup();
            let params = computation.clone().setup();
            let proof = computation.prove(&params);
            let serialized_proof = serde_json::to_string::<G16Proof>(&proof.clone().into()).unwrap();
            let deserialized_proof: G16Proof = serde_json::from_value(serde_json::from_str::<Value>(&serialized_proof).unwrap()).unwrap();
            assert_eq!(proof, deserialized_proof.into())
        }
    }

    #[test]
    fn verify_proof() {
        let computation = program_setup();

        let public_inputs_values = computation.public_inputs_values();
        let public_inputs_values: Vec<_> = public_inputs_values.into_iter().map(Into::into).collect();

        let params = computation.clone().setup();
        let proof = computation.prove(&params);

        let g16proof = proof.into();
        let g16vk = params.vk.into();
        assert!(G16{}.verify_proof(&g16proof, &g16vk, &public_inputs_values));
    }
}
