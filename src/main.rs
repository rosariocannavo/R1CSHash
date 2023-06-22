
use ark_bls12_377::{Fq, Fr};
use ark_ff::{BigInteger, PrimeField, UniformRand};

use ark_r1cs_std::uint;
use ark_sponge::{
poseidon::{constraints::PoseidonSpongeVar, PoseidonSponge},
CryptographicSponge,
};
  

use R1CSHash::poseidon;



fn main() {
    println!("Hello, world!");

    let params = poseidon::get_bls12377_fq_params();
    let mut rng = ark_std::test_rng();

    //let scalar: ark_ff::Fp384<ark_bls12_377::FqParameters> = Fq::rand(&mut rng);

    let scalar: Fq = Fq::new(5.into());




    let mut sponge: PoseidonSponge<ark_ff::Fp384<ark_bls12_377::FqParameters>> = PoseidonSponge::new(&params);
    sponge.absorb(&scalar.into_repr().to_bits_le());
   // sponge.absorb(&scalar);
    let hash = sponge.squeeze_field_elements::<Fq>(1).remove(0);

   // let hash = sponge.squeeze_bytes(1).remove(0);

    println!("{:?}",hash);

}



