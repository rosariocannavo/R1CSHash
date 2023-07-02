use ark_ec::bls12;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{BigInteger, PrimeField};
use ark_nonnative_field::NonNativeFieldVar;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::{fp::FpVar, FieldVar},
    groups::CurveVar,
    pairing::PairingVar,
    ToBitsGadget, ToConstraintFieldGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Field, SynthesisError},
};

use ark_relations::r1cs::ConstraintSystem;

use ark_std::{
    marker::PhantomData,
    rand::{CryptoRng, Rng},
    UniformRand,
};
use std::ops::MulAssign;



//#[derive(Clone)]
struct FqCircuit<I, IV>
where
    I: PairingEngine,
    IV: PairingVar<I>,
{
    c: I::Fr,
    
    ag: I::G1Projective,

    bg: I::G1Projective,
  
    _iv: PhantomData<IV>,
    _i: PhantomData<I>,
}

impl<I, IV> FqCircuit<I, IV>
where
    I: PairingEngine,
    IV: PairingVar<I>,
{
    #[allow(dead_code)]
    pub fn new<R: Rng + CryptoRng>(
        mut rng: &mut R,
    ) -> Self {

        //bg = c * ag
        let c = I::Fr::rand(&mut rng);
        let ag = I::G1Projective::prime_subgroup_generator();

        let mut bg = ag.clone();
       
        bg.mul_assign(c);
        

       /* println!("c: {:?}", c);
        println!("ag: {:?}", ag);
        println!("bg: {:?}", bg);*/

        Self {
            c:c,
            ag: ag,
            bg: bg,
            _iv: PhantomData,
            _i: PhantomData,
        }


    }

}

impl<I, IV> ConstraintSynthesizer<I::Fq> for FqCircuit<I, IV>
where
    I: PairingEngine,
    IV: PairingVar<I>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<I::Fq>) -> Result<(), SynthesisError> {

        let ag = IV::G1Var::new_input(ns!(cs, "ag"), || Ok(self.ag))?;

        let scalar_in_fq = &I::Fq::from_repr(<I::Fq as PrimeField>::BigInt::from_bits_le(
            &self.c.into_repr().to_bits_le(),
        ))
        .unwrap();

        let c = FpVar::new_witness(ns!(cs, "c"), || Ok(scalar_in_fq))?;
        let bits_c = c.to_bits_le()?;

        let mul = ag.scalar_mul_le(bits_c.iter())?;

        let bg = IV::G1Var::new_input(ns!(cs, "bg"), || Ok(self.bg))?;
        

        bg.enforce_equal(&mul)?;

        Ok(())
    }
}

impl<I, IV> Clone for FqCircuit<I, IV>
where
    I: PairingEngine,
    IV: PairingVar<I>,
{
    fn clone(&self) -> Self {
        Self {
            c: self.c,
            ag: self.ag,
            bg: self.bg,    
            _iv: self._iv,
            _i: self._i,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::{
        constraints::PairingVar as IV, Bls12_377 as I, Fr, G1Projective as G1, G2Projective as G2,
    };
    use ark_ec::bls12::Bls12;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_serialize::CanonicalSerialize;
    use ark_std::One;

    use ark_bw6_761::BW6_761 as P;
    use ark_groth16::Groth16;
    use ark_crypto_primitives::{CircuitSpecificSetupSNARK, SNARK};


    #[test]
    fn with_groth() {
        let mut rng = ark_std::test_rng();  

        let circuit = FqCircuit::<I, IV>::new(&mut rng);

        let ag = circuit.ag;
        let c = circuit.c;
        let bg = circuit.bg;
        let iv = circuit._iv;
        let i = circuit._i;

        println!("sto alloppando");
        let (pk, vk) = Groth16::<P>::setup(circuit.clone(), &mut rng).unwrap();
      
        println!("sto alloppando");
        let proof = Groth16::prove(&pk, circuit.clone(), &mut rng).unwrap();
        /*Error here*/
       // let is_verified = Groth16::verify(&vk, &[c, ag, bg,iv, i], &proof).unwrap();
       // assert!(is_verified);

    }
    
    #[test]
    fn preimage_constraints_correctness() {

        //bg = c * ag

        // let ag = ark_bls12_377::G1Projective::prime_subgroup_generator();

        let mut rng = ark_std::test_rng();

        // let c = ark_bls12_377::Fr::rand(&mut rng); // Replace 42 with your desired field element


        // let scalar_in_fq = &ark_bls12_377::Fq::from_repr(<ark_bls12_377::Fq as PrimeField>::BigInt::from_bits_le(
        //     &c.into_repr().to_bits_le(),
        // ))
        // .unwrap();

        // let cag = ag.clone();
        // //let bits_c = c.to_bits_le()?;
        // cag.mul_assign(c);  


        let cs = ConstraintSystem::<<I as PairingEngine>::Fq>::new_ref();
        FqCircuit::<I, IV>::new(&mut rng)
            .generate_constraints(cs.clone())
            .unwrap();
        
        assert!(cs.is_satisfied().unwrap());

    }

}