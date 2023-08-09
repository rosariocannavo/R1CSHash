

use ark_ec::PairingEngine;
use ark_ff::{BigInteger, PrimeField};

use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::CurveVar,
    pairing::PairingVar,
    ToBitsGadget, ToConstraintFieldGadget,
};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};


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
    c1: I::Fr,
    
    A1: I::G1Projective,

    B1: I::G2Projective,
    
    c2: I::Fr,
    
    A2: I::G1Projective,

    B2: I::G2Projective,

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
        //Proving I know A, and B and c such that e(c1A1,B1) * e(c2A2,B2) = T



        // MAKE 1 pairing
        let ag1 = IV::G1Var::new_witness(ns!(cs, "ag1"), || Ok(self.A1))?;
        let bg1 = IV::G2Var::new_witness(ns!(cs, "bg1"), || Ok(self.B1))?;


        let scalar_in_fq1 = &I::Fq::from_repr(<I::Fq as PrimeField>::BigInt::from_bits_le(
            &self.c1.into_repr().to_bits_le(),
        ))
        .unwrap();

        let c1 = FpVar::new_witness(ns!(cs, "c1"), || Ok(scalar_in_fq1))?;
        let bits_c1= c1.to_bits_le()?;
        let ag_c1 = ag1.scalar_mul_le(bits_c1.iter())?;

        
        let pag1 = IV::prepare_g1(&ag_c1)?;
        let pbg1 = IV::prepare_g2(&bg1)?;
        
        let res_g1 =  IV::pairing(pag1, pbg1)?;


        // MAKE 2 pairing

        let ag2 = IV::G1Var::new_witness(ns!(cs, "ag2"), || Ok(self.A2))?;
        let bg2 = IV::G2Var::new_witness(ns!(cs, "bg2"), || Ok(self.B2))?;


        let scalar_in_fq2 = &I::Fq::from_repr(<I::Fq as PrimeField>::BigInt::from_bits_le(
            &self.c2.into_repr().to_bits_le(),
        ))
        .unwrap();

        let c2 = FpVar::new_witness(ns!(cs, "c2"), || Ok(scalar_in_fq2))?;
        let bits_c2= c2.to_bits_le()?;
        let ag_c2 = ag2.scalar_mul_le(bits_c2.iter())?;

        
        let pag2 = IV::prepare_g1(&ag_c2)?;
        let pbg2 = IV::prepare_g2(&bg2)?;
        
        let res_g2 =  IV::pairing(pag2, pbg2)?;

        // MULT 

        let mut res = res_g1 * res_g2;
        
        // T 
        let t_g = IV::GTVar::new_input(ns!(cs, "CT"), || Ok(self.T))?;
        
        t_g.enforce_equal(&res)?;

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
        //ag_c = c * ag
        //tg = e(ag_c, bg)

        //PARING 1
        let c1 = I::Fr::rand(&mut rng);
        let ag1 = I::G1Projective::rand(&mut rng);
        let bg1 = I::G2Projective::rand(&mut rng);

        let mut ag_c1 = ag1.clone();
       
        ag_c1.mul_assign(c1);

        let tg1 = I::pairing(ag_c1, bg1);
        //PARING 2

        let c2 = I::Fr::rand(&mut rng);
        let ag2 = I::G1Projective::rand(&mut rng);
        let bg2 = I::G2Projective::rand(&mut rng);

        let mut ag_c2 = ag2.clone();
       
        ag_c2.mul_assign(c2);
        let tg2 = I::pairing(ag_c2, bg2);

        // MULT 
        let tg = tg1*tg2;
       
        Self {
            c1:c1,
            A1: ag1,
            B1: bg1,
            c2:c2,
            A2: ag2,
            B2: bg2,
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
            c1: self.c1,
            A1: self.A1,
            B1: self.B1,    
            c2: self.c2,
            A2: self.A2,
            B2: self.B2, 
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
        constraints::PairingVar as IV, Bls12_377 as I};
    use ark_relations::r1cs::ConstraintSystem;
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

    //#[test]
    // fn with_groth() {
    //     let mut rng = ark_std::test_rng();  

    //     let circuit = PairingCircuit::<I, IV>::new(&mut rng);

    //     let ag = circuit.A;
    //     let c = circuit.c;
    //     let bg = circuit.B;
    //     let tg = circuit.T;
    //     let iv = circuit._iv;
    //     let i = circuit._i;

    //     let (pk, vk) = Groth16::<P>::setup(circuit.clone(), &mut rng).unwrap();
      
    //     let proof = Groth16::prove(&pk, circuit.clone(), &mut rng).unwrap();

    //     /*Error here*/
    //     //let is_verified = Groth16::verify(&vk, &[c, ag, bg,iv, i], &proof).unwrap();
    //    // assert!(is_verified);

    // }

}