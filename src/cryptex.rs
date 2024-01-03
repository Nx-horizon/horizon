use std::collections::HashMap;
use std::error::Error;
use rand::prelude::SliceRandom;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rayon::prelude::*;
use crate::{addition_chiffres, get_salt, insert_random_stars, xor_crypt};
use crate::kdfwagen::kdfwagen;


fn table3(characters: &str, seed: u64) -> Vec<Vec<Vec<u8>>> {
    let characters: Vec<u8> = characters.bytes().collect();
    let len = characters.len();
    let mut chars: Vec<u8> = characters.to_vec();

    let mut rng = StdRng::seed_from_u64(seed);
    chars.shuffle(&mut rng);

    (0..len).into_par_iter().map(|i| {
        (0..len).into_par_iter().map(|j| {
            (0..len).into_par_iter().map(|k| {
                let idx = (i + j + k) % len;
                chars[idx]
            }).collect::<Vec<u8>>()
        }).collect::<Vec<Vec<u8>>>()
    }).collect::<Vec<Vec<Vec<u8>>>>()
}

pub(crate) fn encrypt3(plain_text: &str, key1: &str, key2: &str, characters: &str, password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let plain_text_with_stars = insert_random_stars(plain_text);
    let table = table3(characters, (addition_chiffres(key2) * addition_chiffres(key1)) as u64);
    let mut char_positions = HashMap::with_capacity(characters.len());
    characters.chars().enumerate().for_each(|(i, c)| {
        char_positions.insert(c, i);
    });

    let mut cipher_text = String::with_capacity(plain_text_with_stars.len());
    let characters_len = characters.len();
    let table_len = table.len();

    let key1_chars: Vec<usize> = key1.chars().map(|c| c as usize % characters_len).collect();
    let key2_chars: Vec<usize> = key2.chars().map(|c| c as usize % characters_len).collect();
    let key1_len = key1_chars.len();
    let key2_len = key2_chars.len();

    for (i, c) in plain_text_with_stars.chars().enumerate() {
        let table_2d = key1_chars[i % key1_len];
        let row = key2_chars[i % key2_len];

        match char_positions.get(&c) {
            Some(col) => {
                let col = col % characters_len;
                if table_2d < table_len && row < table[table_2d].len() && col < table[table_2d][row].len() {
                    cipher_text.push(table[table_2d][row][col] as char);
                } else {
                    return Err("Error: Invalid table dimensions".into());
                }
            },
            None => {
                println!("Character '{}' not found in character set", c);
                return Err("Error: Character not found in character set".into());
            },
        }
    }
    let xor = xor_crypt(&kdfwagen(password.as_bytes(), get_salt().as_bytes(), 30), cipher_text.as_bytes());

    Ok(xor)
}

pub(crate) fn decrypt3(cipher_text: &[u8], key1: &str, key2: &str, characters: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let table = table3(characters, (addition_chiffres(key2) * addition_chiffres(key1)) as u64);
    let cipher_text = xor_crypt(&kdfwagen(password.as_bytes(), get_salt().as_bytes(), 30), cipher_text);
    let cipher_text = String::from_utf8(cipher_text)?;

    let mut plain_text = String::with_capacity(cipher_text.len());
    let characters_len = characters.len();
    let table_len = table.len();

    let key1_chars: Vec<usize> = key1.chars().map(|c| c as usize % characters_len).collect();
    let key2_chars: Vec<usize> = key2.chars().map(|c| c as usize % characters_len).collect();
    let key1_len = key1_chars.len();
    let key2_len = key2_chars.len();

    // Convert characters to Vec<char>
    let characters_vec: Vec<char> = characters.chars().collect();

    for (i, c) in cipher_text.chars().enumerate() {
        let table_2d = key1_chars[i % key1_len];
        let row = key2_chars[i % key2_len];

        if table_2d < table_len && row < table[table_2d].len() {
            if let Some(col) = table[table_2d][row].iter().position(|&x| x == c as u8) {
                plain_text.push(characters_vec[col]);
            } else {
                return Err("Error: Character not found in table".into());
            }
        } else {
            return Err("Error: Invalid table dimensions".into());
        }
    }
    plain_text = plain_text.replace('^', "");
    Ok(plain_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt3_decrypt3() {
        let plain_text = "cest moi le le grand test du matin et je à suis content";
        let key1 = "key1";
        let key2 = "key2";
        let characters = "15^,&X_.w4Uek[?zv>|LOi9;83tgVxCdsrGHj#Ky+<hPQSR@nMDB2Z{cfI0l6-F}7EW$%Ybq'Jo=~:\"](Aa/p!uTN)*`m àé";
        let password = "password";

        // Test encrypt3
        match encrypt3(plain_text, key1, key2, characters, password) {
            Ok(encrypted) => {
                println!("Encrypted: {:?}", encrypted);
                assert_ne!(encrypted, plain_text.as_bytes());

                // Test decrypt3
                match decrypt3(&encrypted, key1, key2, characters, password) {
                    Ok(decrypted) => assert_eq!(decrypted, plain_text),
                    Err(e) => panic!("Decryption failed with error: {:?}", e),
                }
            }
            Err(e) => panic!("Encryption failed with error: {:?}", e),
        }
    }

    #[test]
    fn test_encrypt3() {
        let plain_text = "cest moi le grabd test du matin et je suis content";
        let key1 = "key1";
        let key2 = "key2";
        let characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789! ,^";
        let password = "password";

        // Test encrypt3
        match encrypt3(plain_text, key1, key2, characters, password) {
            Ok(encrypted) => {
                assert_ne!(encrypted, plain_text.as_bytes());
            }
            Err(e) => panic!("Encryption failed with error: {:?}", e),
        }
    }

}