
use ark_bls12_377::{Fq, Fr};
use ark_ff::{BigInteger, PrimeField, UniformRand};

use ark_r1cs_std::uint;
use ark_sponge::{
poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
CryptographicSponge,
};
  

use R1CSHash::poseidon;



// fn main() {
//     println!("Hello, world!");

//     let params = poseidon::get_bls12377_fq_params();
//     let mut rng = ark_std::test_rng();

//     //let scalar: ark_ff::Fp384<ark_bls12_377::FqParameters> = Fq::rand(&mut rng);

//     let scalar: Fq = Fq::new(5.into());




//     let mut sponge: PoseidonSponge<ark_ff::Fp384<ark_bls12_377::FqParameters>> = PoseidonSponge::new(&params);
//     sponge.absorb(&scalar.into_repr().to_bits_le());
//    // sponge.absorb(&scalar);
//     let hash = sponge.squeeze_field_elements::<Fq>(1).remove(0);

//    // let hash = sponge.squeeze_bytes(1).remove(0);

//     println!("{:?}",hash);

// }

use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::Field;
use ark_bls12_381::{Bls12_381, G1Affine, G1Projective};

fn main() {
    // Create a field element and a curve point
    let field_element = ark_bls12_377::Fr::from(42); // Replace 42 with your desired field element
    let curve_point: ark_ec::short_weierstrass_jacobian::GroupProjective<ark_bls12_381::g1::Parameters> = G1Projective::prime_subgroup_generator();

    // Multiply the field element by the curve point
    let multiplied_point: ark_ec::short_weierstrass_jacobian::GroupProjective<ark_bls12_381::g1::Parameters> = curve_point.mul(field_element.into_repr());

    // Convert the result to an affine point for further operations if needed
    let multiplied_point_affine = multiplied_point.into_affine();

    // Print the resulting affine point
    println!("Result: {:?}", multiplied_point_affine);
}



