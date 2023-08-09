

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


#[derive(Clone)]
struct PairingCircuit<I, IV>
where
    I: PairingEngine,
    IV: PairingVar<I>,
{

    c: Vec<I::Fr>,
    
    A: Vec<I::G1Projective>,

    B: Vec<I::G2Projective>,
    
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
        let mut mult_acc;
        for i in 0..=self.c.len() {
            let ag = IV::G1Var::new_witness(ns!(cs, "ag"), || Ok(self.A[i]))?;
            let bg = IV::G2Var::new_witness(ns!(cs, "bg"), || Ok(self.B[i]))?;

            let scalar_in_fq = &I::Fq::from_repr(<I::Fq as PrimeField>::BigInt::from_bits_le(
                &self.c[i].into_repr().to_bits_le(),
            ))
            .unwrap();
    
            let c = FpVar::new_witness(ns!(cs, "c"), || Ok(scalar_in_fq))?;
            let bits_c = c.to_bits_le()?;
            let ag_c = ag.scalar_mul_le(bits_c.iter())?;
    
            let pag = IV::prepare_g1(&ag_c)?;
            let pbg = IV::prepare_g2(&bg)?;
            
            let res_g =  IV::pairing(pag, pbg)?;

            mult_acc *= res_g;
        }

        let t_g = IV::GTVar::new_input(ns!(cs, "CT"), || Ok(self.T))?;
        
        t_g.enforce_equal(&mult_acc)?;

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
        let mut c: Vec<I::Fr> = Vec::new();
        let mut ag: Vec<I::G1Projective> = Vec::new();
        let mut bg: Vec<I::G2Projective> = Vec::new();

        for i in 0..=5 {
            c[i] = I::Fr::rand(&mut rng);
            ag[i] = I::G1Projective::rand(&mut rng);
            bg[i] = I::G2Projective::rand(&mut rng);
        }
        let mut tg_tot;
        let ag_c = ag[0].clone();
        let tg = I::pairing(ag_c, bg[0]);
        tg_tot = tg;
        for j in 1..=5 {
            let ag_c = ag[j].clone();
            let tg = I::pairing(ag_c, bg[j]);
            tg_tot *= tg;
        }
       
        Self {
            c:c,
            A: ag,
            B: bg,
            T: tg_tot,
            _iv: PhantomData,
            _i: PhantomData,
        }

    }

}


// impl<I, IV> Clone for PairingCircuit<I, IV>
// where
//     I: PairingEngine,
//     IV: PairingVar<I>,
// {
//     fn clone(&self) -> Self {
//         Self {
//             c: self.c,
//             A: self.A,
//             B: self.B,    
//             T: self.T,
//             _iv: self._iv,
//             _i: self._i,
//         }
//     }
// }

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
}
//     #[test]
//     fn with_groth() {
//         let mut rng = ark_std::test_rng();  

//         let circuit = PairingCircuit::<I, IV>::new(&mut rng);

//         let ag = circuit.A;
//         let c = circuit.c;
//         let bg = circuit.B;
//         let tg = circuit.T;
//         let iv = circuit._iv;
//         let i = circuit._i;

//         let (pk, vk) = Groth16::<P>::setup(circuit.clone(), &mut rng).unwrap();
      
//         let proof = Groth16::prove(&pk, circuit.clone(), &mut rng).unwrap();

//         /*Error here*/
//         //let is_verified = Groth16::verify(&vk, &[c, ag, bg,iv, i], &proof).unwrap();
//        // assert!(is_verified);

//     }

// }