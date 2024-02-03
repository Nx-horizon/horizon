use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use mac_address::get_mac_address;
use rayon::prelude::*;
use sha3::{Digest, Sha3_512};
use crate::{kdfwagen};
use crate::systemtrayerror::SystemTrayError;
use sysinfo::System;

use crate::prng::{self, Yarrow};

//grossen function
fn table3(size: usize, seed: usize) -> Vec<Vec<Vec<u8>>> {
    let mut characters: Vec<u8> = (0..=255).collect();

    prng::seeded_shuffle(&mut characters, seed);

    return (0..size).into_par_iter().chunks(1000).map(|i_chunk| {
        i_chunk.into_par_iter().map(|i| {
            (0..size).into_par_iter().chunks(1000).map(|j_chunk| {
                j_chunk.into_par_iter().map(|j: usize| {
                    (0..size).map(|k| {
                        let idx: usize = (i + j + k) % size;
                        characters[idx]
                    }).collect::<Vec<u8>>()
                }).collect::<Vec<Vec<u8>>>()
            }).flatten().collect::<Vec<Vec<u8>>>()
        }).collect::<Vec<Vec<Vec<u8>>>>()
    }).flatten().collect::<Vec<Vec<Vec<u8>>>>();
}


fn get_salt() -> String {
    System::name().unwrap() + &System::host_name().unwrap() + &System::os_version().unwrap()  + &System::kernel_version().unwrap()
}

fn stable_indices(word_len: usize, shift: usize) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..word_len).collect();

    indices.sort_unstable_by(|&a, &b| {
        let mut hasher = Sha3_512::new();
        hasher.update(a.to_ne_bytes());
        let hash_a = hasher.finalize();

        let mut hasher = Sha3_512::new();
        hasher.update(b.to_ne_bytes());
        let hash_b = hasher.finalize();

        return hash_a.cmp(&hash_b);
    });

    let shifted_indices: Vec<usize> = indices
        .into_iter()
        .cycle()
        .skip(shift)
        .take(word_len)
        .collect();

    return shifted_indices;
}

fn transpose(word: Vec<u8>, shift: usize) -> Option<Vec<u8>> {
    let word_len = word.len();

    if word_len == 0 || shift >= word_len {
        return None;
    }

    let indices = stable_indices(word_len, shift);

    let output: Vec<u8> = indices.par_iter()
        .map(|&i| word[i])
        .collect();

    return Some(output);
}

pub fn generate_key() -> Vec<u8> {
    let returner = match get_mac_address() {
        Ok(Some(mac_address)) => {
            let mac_address_str = mac_address.to_string();
            let returner = kdfwagen(mac_address_str.as_bytes(), get_salt().as_bytes(), 30);
            hex::encode(returner).as_bytes().to_vec()
        },
        Ok(None) => {
            println!("No MAC address found.");
            Vec::new()
        },
        Err(e) => {
            println!("Error: {}", e);
            Vec::new()
        },
    };

    return returner;
}

fn addition_chiffres(adresse_mac: &Vec<u8>) -> u32 {
    adresse_mac.iter().map(|&x| x as u32).sum()
}

fn generate_key2(seed: &str) -> Result<Vec<u8>, SystemTrayError> {
    if seed.len() < 10 {
        return Err(SystemTrayError::new(4));
    }

    let seed = kdfwagen::kdfwagen(seed.as_bytes(), get_salt().as_bytes(), 30); //change salt by unique pc id

    Ok(hex::encode(seed).as_bytes().to_vec())
}

fn insert_random_stars(mut word: Vec<u8>) -> Vec<u8> {
    let mut rng = Yarrow::new(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
    rng.add_entropy();

    let num_stars: usize = rng.generate_bounded_number((word.len()/2) as u128, (word.len()*2) as u128) as usize;

    // In utf-8, the '^' character is 94
    let mut stars: Vec<u8> = vec![94; num_stars];
    let mut indices: Vec<usize> = (0..=word.len()).collect();

    prng::shuffle(&mut indices);

    for index in indices.into_iter().take(num_stars) {
        word.insert(index, stars.pop().unwrap());
    }

    word.into_iter().collect()
}

fn vz_maker(val1: u32, val2:u32, seed: u64) -> Vec<u8>{
    kdfwagen(&[(val1+val2) as u8,(val1*val2) as u8, (val1%val2) as u8, (val1-val2) as u8, seed as u8], get_salt().as_bytes(), 10)
}

pub(crate) fn encrypt3(plain_text: &str, key1: &Vec<u8>, key2: &Vec<u8>, password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let plain_text = plain_text.as_bytes().to_vec();
    let inter = insert_random_stars(plain_text);

    let val1 = addition_chiffres(key2);
    let val2 = addition_chiffres(key1);

    let mut characters: Vec<u8> = (0..=255).collect();
    let seed: usize = (val2 * val1) as usize;
    let table = table3(characters.len(), seed);

    prng::seeded_shuffle(&mut characters, seed);

    let mut char_positions = HashMap::with_capacity(characters.len());
    characters.iter().enumerate().for_each(|(i, c)| {
        char_positions.insert(c, i);
    });

    let mut cipher_text = Vec::with_capacity(inter.len());
    let table_len = table.len();

    let key1_chars: Vec<usize> = key1.par_iter().map(|&c| c as usize % characters.len()).collect();
    let key2_chars: Vec<usize> = key2.par_iter().map(|&c| c as usize % characters.len()).collect();
    let key1_len = key1_chars.len();
    let key2_len = key2_chars.len();

    for (i, c) in inter.iter().enumerate() {
        let table_2d = key1_chars[i % key1_len] % table_len;
        let row = key2_chars[i % key2_len] % table_len;

        match char_positions.get(c) {
            Some(col) => {
                let col = col % characters.len();

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

    xor_crypt3(&mut cipher_text, &kdfwagen(password.as_bytes(), get_salt().as_bytes(), 30));
    let vz = vz_maker(val1, val2, seed as u64);

    Ok(shift_bits(cipher_text, &vz))
}


pub(crate) fn decrypt3(cipher_text: Vec<u8>, key1: &Vec<u8>, key2: &Vec<u8>, password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut cipher_text = cipher_text.clone();

    let val1 = addition_chiffres(key2);
    let val2 = addition_chiffres(key1);

    let seed: usize = (val2 * val1) as usize;

    let mut characters: Vec<u8> = (0..=255).collect();
    prng::seeded_shuffle(&mut characters, seed);

    let table = table3(characters.len(), seed);

    let mut plain_text: Vec<u8> = Vec::new();
    let table_len = table.len();

    let vz = vz_maker(val1, val2, seed as u64);
    cipher_text = unshift_bits(cipher_text, &vz);
    xor_crypt3(&mut cipher_text, &kdfwagen(password.as_bytes(), get_salt().as_bytes(), 30));

    let key1_chars: Vec<usize> = key1.par_iter().map(|&c| c as usize % characters.len()).collect();
    let key2_chars: Vec<usize> = key2.par_iter().map(|&c| c as usize % characters.len()).collect();
    let key1_len = key1_chars.len();
    let key2_len = key2_chars.len();

    for (i, c) in cipher_text.iter().enumerate() {
        let table_2d = key1_chars[i % key1_len] % table_len;
        let row = key2_chars[i % key2_len] % table_len;

        if table_2d < table_len && row < table[table_2d].len() {
            if let Some(col) = table[table_2d][row].iter().position(|x| x == c) {
                if characters[col] != 94 {
                    plain_text.push(characters[col]);

                }
            } else {
                return Err("Error: String not found in table".into());
            }
        } else {
            return Err("Error: Invalid table dimensions".into());
        }
    }
    
    // let mut plain_text: String = plain_text.into_iter().collect();

    Ok(plain_text)
}

fn xor_crypt3(input: &mut [u8], key: &[u8]) {
    for (i, byte) in input.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

pub fn shift_bits(cipher_text: Vec<u8>, key: &[u8]) -> Vec<u8> {
    cipher_text.par_iter().enumerate().map(|(i, &byte)| {
        let shift_amount = key[i % key.len()];
        let rotated_byte = byte.rotate_left(shift_amount as u32);
        rotated_byte
    }).collect::<Vec<u8>>() // Collect into a Vec<u8>
}

pub fn unshift_bits(cipher_text: Vec<u8>, key: &[u8]) -> Vec<u8> {
    cipher_text.par_iter().enumerate().map(|(i, &byte)| {
        let shift_amount = key[i % key.len()];
        let rotated_byte = byte.rotate_right(shift_amount as u32);
        rotated_byte
    }).collect::<Vec<u8>>() // Collect into a Vec<u8>
}

// pub fn encrypt_file(file_path: &str, key: &[u8]) -> Result<(), Box<dyn Error>> {
//     // Read the file content
//     let mut file = File::open(file_path)?;
//     let mut content = Vec::new();
//     file.read_to_end(&mut content)?;

//     // Perform XOR encryption
//     xor_crypt3(&mut content, key);

//     // Write the encrypted content back to the file
//     let mut file = File::create(file_path)?;
//     file.write_all(&content)?;

//     Ok(())
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table3() {
        let size = 10;

        let table = table3(size, 1234567890);

        for (_i, table_2d) in table.iter().enumerate() {
            for (_j, row) in table_2d.iter().enumerate() {
                for (_k, col) in row.iter().enumerate() {
                    print!("{} ", col);
                }

                println!();
            }

            println!();
            println!();
        }
    }

    #[test]
    fn test_get_salt() {
        let salt = get_salt();
        println!("Salt: {:?}", salt);
    }

    #[test]
    fn test_transpose() {
        let word = "Hello World!".as_bytes().to_vec();

        for shift in 0..word.len() {
            let transposed = transpose(word.clone(), shift).unwrap();

            println!("Shift: {}, Transposed: {:?}", shift, transposed);
        }
    }

    #[test]
    fn test_generate_key() {
        let key = generate_key();

        println!("Key size : {}", key.len());
        println!("Key: {:?}", key);
    }

    #[test]
    fn test_generate_key2() {
        let seed = "0123456789";
        let key = generate_key2(&seed).unwrap();

        println!("Key size : {}", key.len());
        println!("Key: {:?}", key);
    }

    #[test]
    fn test_insert_random_stars() {
        let word = "Hello World!".as_bytes().to_vec();
        let word = insert_random_stars(word);

        println!("Word: {:?}", word);
    }

    #[test]
    fn test_encrypt3_decrypt3() {
        // let plain_text = "cest moi le le grand test du matin et je à suis content";
        let plain_text = "cest moi le le grand test du matin et je à suis content éèù";
        let key1 = "key1".as_bytes().to_vec();
        let key2 = "key2".as_bytes().to_vec();
        let pass = "LeMOTdePAsse34!";

        // Convert plain_text to Vec<u8>
        let plain_text_chars = plain_text.as_bytes().to_vec();

        // Test encrypt3
        match encrypt3(plain_text, &key1, &key2, pass) {
            Ok(encrypted) => {
                println!("Encrypted: {:?}", encrypted);
                assert_ne!(encrypted, plain_text_chars);


                // Test decrypt3
                match decrypt3(encrypted, &key1, &key2, pass) {
                    Ok(decrypted) => {
                        println!("Decrypted: {:?}", decrypted);
                        println!("convert u8: {:?}", String::from_utf8(decrypted.clone()).unwrap());
                        assert_eq!(decrypted, plain_text_chars);
                    },
                    Err(e) => panic!("Decryption failed with error: {:?}", e),
                }
            }
            Err(e) => panic!("Encryption failed with error: {:?}", e),
        }
    }


}