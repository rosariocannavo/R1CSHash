use ark_bls12_377::{Fq, Fr};
use ark_r1cs_std::{fields::fp::FpVar, groups::CurveVar, prelude::*};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
  };

use ark_sponge::poseidon::PoseidonParameters;
use ark_sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
    CryptographicSponge,
  };

use ark_bw6_761::BW6_761 as P;
use ark_groth16::Groth16;
use ark_crypto_primitives::{CircuitSpecificSetupSNARK, SNARK};

use crate::poseidon;


//this circuit want to verify if y = H(x) with x witness
#[derive(Clone)]
pub struct HashVerification {
    pub params: PoseidonParameters<Fq>,

    // The private witness
    pub x: Fq,

    //public input
    pub y: Fq,
}

impl ConstraintSynthesizer<Fq> for HashVerification {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
      let mut sponge_var = PoseidonSpongeVar::new(cs.clone(), &self.params);
  
      let exp_hash_var =
        FpVar::<Fq>::new_input(ns!(cs.clone(), "hash"), || Ok(self.y.clone())).unwrap();
      
    
      let x = 
         FpVar::new_witness(ns!(cs.clone(), "value"), || Ok(self.x.clone())).unwrap();

  
      sponge_var.absorb(&x).unwrap();
  
      let hash_var = sponge_var.squeeze_field_elements(1).unwrap().remove(0); 

  
      hash_var.enforce_equal(&exp_hash_var)?;
  
      Ok(())
    }
  }

  
  #[test]
  fn with_groth_16() {
    let params: PoseidonParameters<ark_ff::Fp384<ark_bls12_377::FqParameters>> = poseidon::get_bls12377_fq_params();

    let mut sponge: PoseidonSponge<ark_ff::Fp384<ark_bls12_377::FqParameters>> = PoseidonSponge::new(&params);
  
    let mut rng = ark_std::test_rng();

    let scalar: ark_ff::Fp384<ark_bls12_377::FqParameters> = Fq::rand(&mut rng);

    sponge.absorb(&scalar);

  
    let hash = sponge.squeeze_field_elements::<Fq>(1).remove(0);

  
    let circuit = HashVerification {
      params: params,
      x: scalar,
      y: hash,
    };
  
    let (pk, vk) = Groth16::<P>::setup(circuit.clone(), &mut rng).unwrap();
  
    let proof = Groth16::prove(&pk, circuit.clone(), &mut rng).unwrap();
  
    let is_verified = Groth16::verify(&vk, &[hash], &proof).unwrap();
  
    assert!(is_verified);
  }
  
  
#[test]
fn preimage_constraints_correctness() {
  let params = poseidon::get_bls12377_fq_params();

  let mut rng = ark_std::test_rng();
  let scalar: ark_ff::Fp384<ark_bls12_377::FqParameters> = Fq::rand(&mut rng);

  let mut sponge = PoseidonSponge::new(&params);
  
  sponge.absorb(&scalar);

  let hash = sponge.squeeze_field_elements::<Fq>(1).remove(0);

  let circuit = HashVerification {
      params: params,
      x: scalar,
      y: hash,
    };

  let cs = ConstraintSystem::<Fq>::new_ref();

  circuit.generate_constraints(cs.clone()).unwrap();

  let is_satisfied = cs.is_satisfied().unwrap();
  if !is_satisfied {
    // find the offending constraint
    println!("{:?}", cs.which_is_unsatisfied());
  }
  assert!(is_satisfied);

}
  