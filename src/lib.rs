#[macro_use]
extern crate json;

#[macro_use]
extern crate lazy_static;

mod parameters;
pub mod poseidon;
mod r1cs_hash;
mod r1cs_key;
mod r1cs_key_test;

mod r1cs_key_gadget;

mod r1cs_pairing;

mod r1cs_pairing_with_mul;

mod r1cs_pairing_sum;

mod r1cs_pairing_iteration;

