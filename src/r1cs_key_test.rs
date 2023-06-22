use ark_bls12_377::{Fq, G1Projective};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_ff::{ PrimeField};
use ark_relations::{
    ns,
    r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError},
  };


use ark_ec::{ProjectiveCurve};


#[derive(Clone)]
struct KeyVerification {
    //witness
    x: Fq,

    //public input
    y_x: Fq,
    y_y: Fq,
    y_z: Fq,
}

impl ConstraintSynthesizer<Fq> for KeyVerification {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
  
        let generator = G1Projective::prime_subgroup_generator();

        let exp_y_x = 
            FpVar::new_input(ns!(cs.clone(), "exp_x"), || Ok(self.y_x.clone())).unwrap();

        let exp_y_y =
            FpVar::new_input(ns!(cs.clone(), "exp_y"), || Ok(self.y_y.clone())).unwrap();

        let exp_y_z =
            FpVar::new_input(ns!(cs.clone(), "exp_z"), || Ok(self.y_z.clone())).unwrap();

        //let x_var = FpVar::new_witness(ns!(cs.clone(), "value"), || Ok(self.x.clone())).unwrap();

        let multiplied_point = generator.mul(self.x.into_repr());
        
        println!("{:?}", multiplied_point);

        let calc_y_x= 
            FpVar::new_witness(ns!(cs.clone(), "calc_x"), || Ok(multiplied_point.x)).unwrap();

        let calc_y_y= 
            FpVar::new_witness(ns!(cs.clone(), "calc_y"), || Ok(multiplied_point.y)).unwrap();


        let calc_y_z= 
            FpVar::new_witness(ns!(cs.clone(), "calc_z"), || Ok(multiplied_point.z)).unwrap();


        calc_y_x.enforce_equal(&exp_y_x)?;
        calc_y_y.enforce_equal(&exp_y_y)?;
        calc_y_z.enforce_equal(&exp_y_z)?;
  
        Ok(())
    }
  }


  #[test]
  fn with_groth_16() {
    use ark_bw6_761::BW6_761 as P;
    use ark_groth16::Groth16;
    use ark_crypto_primitives::{CircuitSpecificSetupSNARK, SNARK};

    let mut rng = ark_std::test_rng();

    let field_element = ark_bls12_377::Fq::from(42); // Replace 42 with your desired field element
    let generator = G1Projective::prime_subgroup_generator();

    // Multiply the field element by the curve point
    let multiplied_point = generator.mul(field_element.into_repr());

    let circuit = KeyVerification {
      x: field_element,
      y_x: multiplied_point.x,
      y_y: multiplied_point.y,
      y_z: multiplied_point.z,
    };
  
    let (pk, vk) = Groth16::<P>::setup(circuit.clone(), &mut rng).unwrap();
  
    let proof = Groth16::prove(&pk, circuit.clone(), &mut rng).unwrap();

    let is_verified = Groth16::verify(&vk, &[multiplied_point.x, multiplied_point.y, multiplied_point.z], &proof).unwrap();
  
    assert!(is_verified);
  }
  

#[test]
fn preimage_constraints_correctness() {

    let field_element = ark_bls12_377::Fq::from(42); // Replace 42 with your desired field element
    let generator = G1Projective::prime_subgroup_generator();

    // Multiply the field element by the curve point
    let multiplied_point = generator.mul(field_element.into_repr());
    println!("{:?}", multiplied_point);


    let circuit = KeyVerification {
        x: field_element,
        y_x: multiplied_point.x,
        y_y: multiplied_point.y,
        y_z: multiplied_point.z,
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