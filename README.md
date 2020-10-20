<h1>Project Description</h1>

<hr>

This programm uses RSA sign and verify functions from openssl library to emulate work of car's trinket.

<h2>Algorithm</h2>

Let's assume that public key is hardcoded to the car at the dealership.

 Step's to open the car:
 * trinket broadcast his public key
 * car listen to the broadcast and check if public key is in it's internal list of keys
 * if check successful car sends challenge the trinket
 * trinket responds with signed challenge
 * car verify response and open the door if response is verified
 
 Since challenge generated randomly each time, simple copying trinket messages won't open the car.

<h2>How to build and run</h2>

git clone https://github.com/NeXachu/CryptoDZ2.git

cd CryptoDZ2/

cargo build && cargo run

<hr>

*Note:Sample of the output is in file sample.txt*
