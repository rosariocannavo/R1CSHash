use ark_bls12_377::{constraints::G1Var,Fq, Fr, G1Projective, Bls12_377};
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

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::Field;
struct KeyVerification {
    //witness
    x: Fr,

    //public input
    y: G1Projective,
}

impl ConstraintSynthesizer<Fq> for KeyVerification {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
  
        
        let generator = G1Projective::prime_subgroup_generator();

        let exp_y = 
            G1Var::new_input(ns!(cs.clone(), "point"), || Ok(self.y.clone())).unwrap();

       
    //   let x = 
    //      FpVar::new_witness(ns!(cs.clone(), "value"), || Ok(self.x.clone())).unwrap();

        let fr_var = cs.new_witness_variable(|| Ok(self.x))?;

        let fr_var = ark_r1cs_std::alloc::


        let multiplied_point: ark_ec::short_weierstrass_jacobian::GroupProjective<ark_bls12_377::g1::Parameters> = generator.mul(&fr_var);

  

  
      hash_var.enforce_equal(&exp_hash_var)?;
  
      Ok(())
    }
  }
