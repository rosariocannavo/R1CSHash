

use ark_ff::{BigInteger, PrimeField, Field};

use ark_bls12_381::{Fq};

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
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};


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
        //Proving I know A, and B and c such that e(c_i*A_i,B_i) = T
        // let mut mult_acc;
        // for i in 0..=self.c.len() {
            
        //     let ag = IV::G1Var::new_witness(ns!(cs, "ag"), || Ok(self.A[i]))?;
        //     let bg = IV::G2Var::new_witness(ns!(cs, "bg"), || Ok(self.B[i]))?;

        //     let scalar_in_fq = &I::Fq::from_repr(<I::Fq as PrimeField>::BigInt::from_bits_le(
        //         &self.c[i].into_repr().to_bits_le(),
        //     ))
        //     .unwrap();
    
        //     let c = FpVar::new_witness(ns!(cs, "c"), || Ok(scalar_in_fq))?;
        //     let bits_c = c.to_bits_le()?;
        //     let ag_c = ag.scalar_mul_le(bits_c.iter())?;
    
        //     let pag = IV::prepare_g1(&ag_c)?;
        //     let pbg = IV::prepare_g2(&bg)?;
            
        //     let res_g =  IV::pairing(pag, pbg)?;

        //     mult_acc *= res_g;
        // }

        let t_g = IV::GTVar::new_input(ns!(cs, "CT"), || Ok(self.T))?;
        


        let mut ps = Vec::new();
        let mut qs = Vec::new();

        for i in 0..self.A.len() {
            let bg = IV::G2Var::new_witness(ns!(cs, "bg"), || Ok(self.B[i]))?;
            let ag = IV::G1Var::new_witness(ns!(cs, "ag"), || Ok(self.A[i]))?;
            let pag = IV::prepare_g1(&ag)?;
            let pbg = IV::prepare_g2(&bg)?;
            ps.push(pag);
            qs.push(pbg);
        }
                
        let c_ml = IV::miller_loop(&ps, &qs)?;
        let res = IV::final_exponentiation(&c_ml).unwrap();


        println!("{:?}", res);

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
    
        let mut ag: Vec<I::G1Projective> = Vec::new();  
        let mut bg: Vec<I::G2Projective> = Vec::new();

        for _ in 0..=5 {
            ag.push(I::G1Projective::rand(&mut rng));
            bg.push(I::G2Projective::rand(&mut rng));
        }


       // let mut accumulator = I::Fqk::zero(); // Accumulator initialized to the identity element of the target group

        for i in 0..ag.len() {
            let g1_point = &ag[i];
            let g2_point = &bg[i];
        

            // Perform the squaring operation in the Miller loop
            //accumulator *=
            let m_l = I::miller_loop([&(g1_point.into_affine().into(), 
                               g2_point.into_affine().into()),
                            ]);

            let res  = I::final_exponentiation(&m_l);
        
            accumulator  *= res;
        }
        Self {
            A: ag,
            B: bg,
            T: accumulator,
            _iv: PhantomData,
            _i: PhantomData,
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
}
