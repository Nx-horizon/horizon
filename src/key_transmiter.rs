use double_ratchet_2::ratchet::{Ratchet, RatchetEncHeader};

fn standard(){

    let sk = [1; 32];                                                 // Initial Key created by a symmetric key agreement protocol
    let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);        // Creating Bobs Ratchet (returns Bobs PublicKey)
    let mut alice_ratchet = Ratchet::init_alice(sk, public_key);      // Creating Alice Ratchet with Bobs PublicKey
    let data = b"Hello World".to_vec();                               // Data to be encrypted
    let ad = b"Associated Data";                                      // Associated Data

    let (header, encrypted, nonce) = alice_ratchet.ratchet_encrypt(&data, ad);   // Encrypting message with Alice Ratchet (Alice always needs to send the first message)
    let decrypted = bob_ratchet.ratchet_decrypt(&header, &encrypted, &nonce, ad); // Decrypt message with Bobs Ratchet
    assert_eq!(data, decrypted)
}

fn standard_lost_message(){
    let sk = [1; 32];                                                 // Initial Key created by a symmetric key agreement protocol
    let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);        // Creating Bobs Ratchet (returns Bobs PublicKey)
    let mut alice_ratchet = Ratchet::init_alice(sk, public_key);      // Creating Alice Ratchet with Bobs PublicKey
    let data = b"Hello World".to_vec();                               // Data to be encrypted
    let ad = b"Associated Data";                                      // Associated Data

    let (header1, encrypted1, nonce1) = alice_ratchet.ratchet_encrypt(&data, ad); // Lost message
    let (header2, encrypted2, nonce2) = alice_ratchet.ratchet_encrypt(&data, ad); // Successful message

    let decrypted2 = bob_ratchet.ratchet_decrypt(&header2, &encrypted2, &nonce2, ad); // Decrypting second message first
    let decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1, &nonce1, ad); // Decrypting latter message

    let comp = decrypted1 == data && decrypted2 == data;
    assert!(comp);
}

fn encrypt_before_first_msg(){
    let sk = [1; 32];
    let ad = b"Associated Data";
    let (mut bob_ratchet, _) = Ratchet::init_bob(sk);
    let data = b"Hello World".to_vec();

    let (_, _, _) = bob_ratchet.ratchet_encrypt(&data, ad);
}

fn encrypt_after_first_msg(){
    let sk = [1; 32];

    let (mut bob_ratchet, public_key) = Ratchet::init_bob(sk);
    let mut alice_ratchet = Ratchet::init_alice(sk, public_key);

    let data = b"Hello World".to_vec();
    let ad = b"Associated Data";

    let (header1, encrypted1, nonce1) = alice_ratchet.ratchet_encrypt(&data, ad);
    let _decrypted1 = bob_ratchet.ratchet_decrypt(&header1, &encrypted1, &nonce1, ad);

    let (header2, encrypted2, nonce2) = bob_ratchet.ratchet_encrypt(&data, ad);
    let decrypted2 = alice_ratchet.ratchet_decrypt(&header2, &encrypted2, &nonce2, ad);

    assert_eq!(data, decrypted2);

}

fn example_encrypted_header(){
    let sk = [0; 32];
    let shared_hka = [1; 32];
    let shared_nhkb = [2; 32];

    let (mut bob_ratchet, public_key) = RatchetEncHeader::init_bob(sk, shared_hka, shared_nhkb);
    let mut alice_ratchet = RatchetEncHeader::init_alice(sk, public_key, shared_hka, shared_nhkb);
    let data = b"Hello World".to_vec();
    let ad = b"Associated Data";

    let (header, encrypted, nonce) = alice_ratchet.ratchet_encrypt(&data, ad);
    let decrypted = bob_ratchet.ratchet_decrypt(&header, &encrypted, &nonce, ad);
    assert_eq!(data, decrypted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard() {
        standard();
    }

    #[test]
    fn test_standard_lost_message() {
        standard_lost_message();
    }

    #[test]
    fn test_encrypt_before_first_msg() {
        //encrypt_before_first_msg();
    }

    #[test]
    fn test_encrypt_after_first_msg() {
        encrypt_after_first_msg();
    }

    #[test]
    fn test_example_encrypted_header() {
        example_encrypted_header();
    }
}