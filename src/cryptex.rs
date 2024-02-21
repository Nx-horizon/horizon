

//TODO encrypt file and picture here

use std::collections::HashMap;
use std::error::Error;
use blake3::Hasher;
use rayon::prelude::*;
use crate::{addition_chiffres, get_salt, KEY_LENGTH, nebula, NUM_ITERATIONS, shift_bits, table3, unshift_bits, vz_maker, xor_crypt3};
use crate::kdfwagen::kdfwagen;

pub(crate) fn encrypt_file(plain_text: Vec<u8>, key1: &Vec<u8>, key2: &Vec<u8>, password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let inter = plain_text;

    let val1 = addition_chiffres(key2);
    let val2 = addition_chiffres(key1);

    let mut characters: Vec<u8> = (0..=255).collect();
    let seed= val2 * val1;
    let table = table3(256, seed);

    nebula::seeded_shuffle(&mut characters, seed as usize);

    let char_positions: HashMap<_, _> = characters.par_iter().enumerate().map(|(i, &c)| (c, i)).collect();


    let table_len = 256;

    let key1_chars: Vec<usize> = key1.into_par_iter().map(|&c| c as usize % 256).collect();
    let key2_chars: Vec<usize> = key2.into_par_iter().map(|&c| c as usize % 256).collect();
    let key1_len = KEY_LENGTH;
    let key2_len = KEY_LENGTH;

    let mut cipher_text: Vec<_> = inter.par_iter().enumerate().filter_map(|(i, c)| {
        let table_2d = key1_chars[i % key1_len] % table_len;
        let row = key2_chars[i % key2_len] % table_len;

        match char_positions.get(c) {
            Some(col) => {
                let col = col % 256;

                if table_2d < table_len && row < table[table_2d].len() && col < table[table_2d][row].len() {
                    Some(table[table_2d][row][col])
                } else {
                    None
                }
            },
            None => {
                println!("Character '{}' not found in character set", c);
                None
            },
        }
    }).collect();

    xor_crypt3(&mut cipher_text, &kdfwagen(password.as_bytes(), get_salt().as_bytes(), NUM_ITERATIONS));
    let vz = vz_maker(val1, val2, seed);

    Ok(shift_bits(cipher_text, &vz))
}


pub(crate) fn decrypt_file(cipher_text: Vec<u8>, key1: &Vec<u8>, key2: &Vec<u8>, password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut cipher_text = cipher_text.clone();

    let val1 = addition_chiffres(key2);
    let val2 = addition_chiffres(key1);

    let seed = val2 * val1 ;

    let mut characters: Vec<u8> = (0..=255).collect();
    nebula::seeded_shuffle(&mut characters, seed as usize);

    let table = table3(256, seed);

    let table_len = 256;

    let vz = vz_maker(val1, val2, seed);
    cipher_text = unshift_bits(cipher_text, &vz);
    xor_crypt3(&mut cipher_text, &kdfwagen(password.as_bytes(), get_salt().as_bytes(), NUM_ITERATIONS));

    let key1_chars: Vec<usize> = key1.into_par_iter().map(|&c| c as usize % 256).collect();
    let key2_chars: Vec<usize> = key2.into_par_iter().map(|&c| c as usize % 256).collect();
    let key1_len = KEY_LENGTH;
    let key2_len = KEY_LENGTH;

    let plain_text: Vec<_> = cipher_text.par_iter().enumerate().filter_map(|(i, c)| {
        let table_2d = key1_chars[i % key1_len] % table_len;
        let row = key2_chars[i % key2_len] % table_len;

        if table_2d < table_len && row < table[table_2d].len() {
            table[table_2d][row].iter().position(|x| x == c).map(|col| characters[col])
        } else {
            None
        }
    }).collect();

    Ok(plain_text)
}

pub fn cipher_key_transmiter(key1: &[u8], seed: Vec<u8>) -> HashMap<Vec<u8>, [u8; 64]> {
    let mut key_storage = HashMap::new();

    let v1 = kdfwagen(key1, get_salt().as_bytes(), 5);

    let mut seed2 = seed.clone();

    xor_crypt3(&mut seed2, &v1);
    let retour = shift_bits(seed2, &kdfwagen(&v1, get_salt().as_bytes(), 5));

    let mut inner_hasher = Hasher::new();
    inner_hasher.update(&seed);
    let mut inner_hash = [0; 64];
    inner_hasher.finalize_xof().fill(&mut inner_hash);

    key_storage.insert(retour, inner_hash);

    key_storage
}

#[cfg(test)]
mod tests {
    use super::*; // Import the function and necessary modules

    #[test]
    fn test_cipher_key_transmitter() {
        // Define input values for testing
        let key1 = vec![1, 2, 3, 4, 5];
        let seed = "pommedeterre".as_bytes().to_vec();


        let key_storage = cipher_key_transmiter(&key1, seed);
        println!("{:?}",key_storage);

        for (key,_value) in key_storage{
            println!("{}", String::from_utf8_lossy(&key));
        }

        //assert_eq!(key_storage.len(), 1);
    }
}
