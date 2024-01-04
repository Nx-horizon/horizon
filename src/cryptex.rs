use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Write};
use rand::prelude::SliceRandom;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rayon::prelude::*;
use crate::{addition_chiffres, insert_random_stars};

//grossen function
fn table3(characters: &str, seed: u64) -> Vec<Vec<Vec<String>>> {
    let characters: Vec<String> = characters.chars().map(|c| c.to_string()).collect();
    let len = characters.len();
    let mut chars: Vec<String> = characters.to_vec();

    let mut rng = StdRng::seed_from_u64(seed);
    chars.shuffle(&mut rng);

    (0..len).into_par_iter().map(|i| {
        (0..len).into_par_iter().map(|j| {
            (0..len).into_par_iter().map(|k| {
                let idx = (i + j + k) % len;
                chars[idx].clone()
            }).collect::<Vec<String>>()
        }).collect::<Vec<Vec<String>>>()
    }).collect::<Vec<Vec<Vec<String>>>>()
}

pub(crate) fn encrypt3(plain_text: &str, key1: &str, key2: &str, characters: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let inter = insert_random_stars(plain_text);
    let plain_text_chars: Vec<String> = inter.chars().map(|c| c.to_string()).collect();
    let table = table3(characters, (addition_chiffres(key2) * addition_chiffres(key1)) as u64);
    let mut char_positions = HashMap::with_capacity(characters.len());
    characters.chars().enumerate().for_each(|(i, c)| {
        char_positions.insert(c, i);
    });

    let mut cipher_text = Vec::with_capacity(plain_text_chars.len());
    let characters_len = characters.len();
    let table_len = table.len();

    let key1_chars: Vec<usize> = key1.chars().map(|c| c as usize % characters_len).collect();
    let key2_chars: Vec<usize> = key2.chars().map(|c| c as usize % characters_len).collect();
    let key1_len = key1_chars.len();
    let key2_len = key2_chars.len();

    for (i, c) in plain_text_chars.iter().enumerate() {
        let table_2d = key1_chars[i % key1_len] % table_len;
        let row = key2_chars[i % key2_len] % table_len;

        match char_positions.get(&c.chars().next().unwrap()) {
            Some(col) => {
                let col = col % characters_len;
                if table_2d < table_len && row < table[table_2d].len() && col < table[table_2d][row].len() {
                    cipher_text.push(table[table_2d][row][col].clone());
                } else {
                    return Err(format!("Error: Invalid table dimensions. table_2d: {}, row: {}, col: {}", table_2d, row, col).into());
                }
            },
            None => {
                println!("Character '{}' not found in character set", c);
                return Err("Error: Character not found in character set".into());
            },
        }
    }

    Ok(cipher_text)
}

pub(crate) fn decrypt3(cipher_text: &[String], key1: &str, key2: &str, characters: &str) -> Result<String, Box<dyn Error>> {
    let table = table3(characters, (addition_chiffres(key2) * addition_chiffres(key1)) as u64);

    let mut plain_text = String::new();
    let characters_len = characters.len();
    let table_len = table.len();

    let key1_chars: Vec<usize> = key1.chars().map(|c| c as usize % characters_len).collect();
    let key2_chars: Vec<usize> = key2.chars().map(|c| c as usize % characters_len).collect();
    let key1_len = key1_chars.len();
    let key2_len = key2_chars.len();

    for (i, c) in cipher_text.iter().enumerate() {
        let table_2d = key1_chars[i % key1_len] % table_len;
        let row = key2_chars[i % key2_len] % table_len;

        if table_2d < table_len && row < table[table_2d].len() {
            if let Some(col) = table[table_2d][row].iter().position(|x| x == c) {
                plain_text.push_str(&characters.chars().nth(col).unwrap().to_string());
            } else {
                return Err("Error: String not found in table".into());
            }
        } else {
            return Err("Error: Invalid table dimensions".into());
        }
    }
    plain_text = plain_text.replace('^', "");
    Ok(plain_text)
}

fn xor_crypt3(input: &mut [u8], key: &[u8]) {
    for (i, byte) in input.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}
pub fn encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn Error>> {
    // Read the file content
    let mut file = File::open(file_path)?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)?;

    // Perform XOR encryption
    xor_crypt3(&mut content, key);

    // Write the encrypted content back to the file
    let mut file = File::create(file_path)?;
    file.write_all(&content)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::kdfwagen::kdfwagen;
    use super::*;

    #[test]
    fn test_encrypt3_decrypt3() {
        let plain_text = "cest moi le le grand test du matin et je à suis content";
        let key1 = "key1";
        let key2 = "key2";
        let characters = "15^,&X_.w4Uek[?zv>|LOi9;83tgVxCdsrGHj#Ky+<hPQSR@nMDB2Z{cfI0l6-F}7EW$%Ybq'Jo=~:\"](Aa/p!uTN)*`màéÃ  ";

        // Convert plain_text to Vec<String>
        let plain_text_chars: Vec<String> = plain_text.chars().map(|c| c.to_string()).collect();

        // Test encrypt3
        match encrypt3(plain_text, key1, key2, characters) {
            Ok(encrypted) => {
                println!("Encrypted: {:?}", encrypted);
                assert_ne!(encrypted, plain_text_chars);

                // Convert encrypted to Vec<String>
                let encrypted_str: Vec<String> = encrypted.iter().map(|c| c.to_string()).collect();

                // Test decrypt3
                match decrypt3(&encrypted_str, key1, key2, characters) {
                    Ok(decrypted) => {
                        println!("Decrypted: {:?}", decrypted);
                        assert_eq!(decrypted, plain_text);
                    },
                    Err(e) => panic!("Decryption failed with error: {:?}", e),
                }
            }
            Err(e) => panic!("Encryption failed with error: {:?}", e),
        }
    }

    #[test]
    fn test_encrypt_file() {
        // Specify the file path
        let file_path = "";

        // Get the original content of the file
        let mut file = File::open(file_path).unwrap();
        let mut original_content = Vec::new();
        file.read_to_end(&mut original_content).unwrap();

        // Encrypt the file
        let key_vec = kdfwagen(b"password", b"salt", 100);
        println!("Key: {:?}", key_vec);
        encrypt_file(file_path, &key_vec).unwrap();

        // Get the encrypted content of the file
        let mut file = File::open(file_path).unwrap();
        let mut encrypted_content = Vec::new();
        file.read_to_end(&mut encrypted_content).unwrap();

        // Check that the content has changed

    }


}