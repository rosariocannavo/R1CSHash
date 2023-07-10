
use ark_bls12_377::{ G1Projective, G2Projective, Bls12_377,Fq, G1Affine, G2Affine, Fr, constraints::G1Var, constraints::G2Var, constraints::G1PreparedVar, constraints::G2PreparedVar, constraints::Fq12Var};
use ark_ec::bls12;
use ark_ec::prepare_g1;
use ark_ec::prepare_g2;
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{BigInteger, PrimeField};
use ark_nonnative_field::NonNativeFieldVar;
use ark_r1cs_std::pairing::mnt4::GTVar;
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
struct PairingCircuit<I, IV>
where
    I: PairingEngine,
    IV: PairingVar<I>,
{
    c: I::Fr,
    
    A: I::G1Projective,

    B: I::G2Projective,
    
    T: I::Fqk,

    _iv: PhantomData<IV>,
    _i: PhantomData<I>,
}



impl<I, IV> ConstraintSynthesizer<I::Fq> for PairingCircuit<I, IV>
where
    I: PairingEngine,
    IV: PairingVar<I>,
    IV::GTVar: ToConstraintFieldGadget<I::Fq>,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<I::Fq>) -> Result<(), SynthesisError> {
        //Proving I know A, and B and c such that e(cA,B) = T

        let ag = IV::G1Var::new_witness(ns!(cs, "ag"), || Ok(self.A))?;
        let bg = IV::G2Var::new_witness(ns!(cs, "bg"), || Ok(self.B))?;
        
        let pag = IV::prepare_g1(&ag)?;
        let pbg = IV::prepare_g2(&bg)?;
        
        let res =  IV::pairing(pag, pbg)?;

        let ct = IV::GTVar::new_input(ns!(cs, "CT"), || Ok(self.T))?;
        
        ct.enforce_equal(&res)?;

        Ok(())

    }

}

impl<I, IV> PairingCircuit<I, IV>
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
        let ag = I::G1Projective::rand(&mut rng);
        let bg = I::G2Projective::rand(&mut rng);

        let tg = I::pairing(ag, bg);
       
         

        Self {
            c:c,
            A: ag,
            B: bg,
            T: tg,
            _iv: PhantomData,
            _i: PhantomData,
        }


    }

}


impl<I, IV> Clone for PairingCircuit<I, IV>
where
    I: PairingEngine,
    IV: PairingVar<I>,
{
    fn clone(&self) -> Self {
        Self {
            c: self.c,
            A: self.A,
            B: self.B,    
            T: self.T,
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
    fn preimage_constraints_correctness() {
        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<<I as PairingEngine>::Fq>::new_ref();

        PairingCircuit::<I, IV>::new(&mut rng)
            .generate_constraints(cs.clone())
            .unwrap();
        
        assert!(cs.is_satisfied().unwrap());

    }

    #[test]
    fn with_groth() {
        let mut rng = ark_std::test_rng();  

        let circuit = PairingCircuit::<I, IV>::new(&mut rng);

        let ag = circuit.A;
        let c = circuit.c;
        let bg = circuit.B;
        let tg = circuit.T;
        let iv = circuit._iv;
        let i = circuit._i;

        let (pk, vk) = Groth16::<P>::setup(circuit.clone(), &mut rng).unwrap();
      
        let proof = Groth16::prove(&pk, circuit.clone(), &mut rng).unwrap();

        /*Error here*/
        //let is_verified = Groth16::verify(&vk, &[c, ag, bg,iv, i], &proof).unwrap();
       // assert!(is_verified);

    }

}