use openssl::sign::{Signer, Verifier};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use rand::Rng;
use rand::distributions::Alphanumeric;
use std::str;

fn generate_random_string(n:usize) -> String {
    let str:String =rand::thread_rng().sample_iter(&Alphanumeric).take(n).collect::<String>(); 
   return str;
}

fn main() {

// Generate a keypair for trinket

let trinket_rsa = Rsa::generate(2048).unwrap();
let trinket_keypair = PKey::from_rsa(trinket_rsa).unwrap();
let trinket_pubkey: Vec<u8> =trinket_keypair.public_key_to_pem().unwrap();
let trinket_pubkey_printable =str::from_utf8(trinket_pubkey.as_slice()).unwrap();

// Generate a keypair for car

let car_rsa = Rsa::generate(2048).unwrap();
let car_keypair = PKey::from_rsa(car_rsa).unwrap();
let car_pubkey: Vec<u8> =car_keypair.public_key_to_pem().unwrap();
let car_pubkey_printable =str::from_utf8(car_pubkey.as_slice()).unwrap();

println!("(registration) {0} (pubkey1 written to car),\n {1} (pubkey2 written to trinket)",trinket_pubkey_printable,car_pubkey_printable);

//Generate data
let message=generate_random_string(2048);

//Sign generated data
let mut signer = Signer::new(MessageDigest::sha256(), &trinket_keypair).unwrap();
signer.update(message.as_bytes()).unwrap();
let trinket_signature = signer.sign_to_vec().unwrap();

println!("(handshake)trinket->car {0:?} (signature), {1} (message)",trinket_signature,message);

// Verify the data
let mut verifier = Verifier::new(MessageDigest::sha256(), &trinket_keypair).unwrap();
verifier.update(message.as_bytes()).unwrap();
let trinket_verified=verifier.verify(&trinket_signature).unwrap();
assert!(trinket_verified);

println!("car->trinket trinked verified:{0}",trinket_verified);

// Generate data
let message2=generate_random_string(2048);

//Sign generated data
let mut signer = Signer::new(MessageDigest::sha256(), &car_keypair).unwrap();
signer.update(message2.as_bytes()).unwrap();
let car_signature = signer.sign_to_vec().unwrap();

println!("(challenge)car->trinket {0:?} (signature), {1} (message)",car_signature,message2);

//Verify the data
let mut verifier = Verifier::new(MessageDigest::sha256(), &car_keypair).unwrap();
verifier.update(message2.as_bytes()).unwrap();
let car_verified=verifier.verify(&car_signature).unwrap();
assert!(car_verified);

println!("trinked->car car verified:{0}",car_verified);

if car_verified && trinket_verified {println!("Open")};
}
