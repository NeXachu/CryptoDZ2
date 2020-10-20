/*
 * Tecnically this should be one way verification, since trinket shouldn't
 * challenge the car to verify that car is the right one.
 * Step's to open the car:
 * 1) trinket broadcasts his public key
 * 2) car listen broadcast and check if public key is in it's list
 * 3) if check successful car challenge the trinket
 * 4) trinket responds with signed challenge
 * 5) car verify and open the door
 * 
 * Since challenge generated randomly each time, simple copying the trinket messages won't open the car
 */
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

println!("(registration) {0} (pubkey1 written to car)",trinket_pubkey_printable);

println!("(handshake) trinket->car {0} (trinket pubkey)",trinket_pubkey_printable);

//Generate challenge
let message=generate_random_string(2048);

println!("(challenge) car->trinket {0}",message);

//Sign generated data
let mut signer = Signer::new(MessageDigest::sha256(), &trinket_keypair).unwrap();
signer.update(message.as_bytes()).unwrap();
let trinket_signature = signer.sign_to_vec().unwrap();

println!("(handshake)trinket->car {1} (message),{0:?} (signature)",trinket_signature,message);

// Verify the data
let mut verifier = Verifier::new(MessageDigest::sha256(), &trinket_keypair).unwrap();
verifier.update(message.as_bytes()).unwrap();
let trinket_verified=verifier.verify(&trinket_signature).unwrap();
assert!(trinket_verified);

println!("car->trinket trinked verified:{0}",trinket_verified);


if trinket_verified {println!("car opened the door")};
}
