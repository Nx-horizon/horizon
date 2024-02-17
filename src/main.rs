mod systemtrayerror;
mod kdfwagen;
mod cryptex;
mod nebula;

use std::collections::HashMap;
use std::error::Error;
use std::time::{SystemTime, UNIX_EPOCH};
use mac_address::get_mac_address;
use rayon::prelude::*;
use crate::systemtrayerror::SystemTrayError;
use sysinfo::System;
use crate::kdfwagen::kdfwagen;
use crate::nebula::Nebula;


const NUM_ITERATIONS: usize = 10;
const KEY_LENGTH: usize = 512;

fn table3(size: usize, seed: u64) -> Vec<Vec<Vec<u8>>> {
    let mut characters: Vec<u8> = (0..=255).collect();

    nebula::seeded_shuffle(&mut characters, seed as usize);

    (0..size).into_par_iter().chunks(1000).map(|i_chunk| {
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
    }).flatten().collect::<Vec<Vec<Vec<u8>>>>()
}


fn get_salt() -> String {
    System::name().unwrap() + &System::host_name().unwrap() + &System::os_version().unwrap()  + &System::kernel_version().unwrap()
}


pub fn generate_key() -> Vec<u8> {

    match get_mac_address() {
        Ok(Some(mac_address)) => {
            let mac_address_str = mac_address.to_string();
            let returner = kdfwagen(mac_address_str.as_bytes(), get_salt().as_bytes(), NUM_ITERATIONS);
            returner
        },
        Ok(None) => {
            eprintln!("No MAC address found."); //TODO use systemTrayError
            Vec::new()
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            Vec::new()
        },
    }

}

fn addition_chiffres(adresse_mac: &[u8]) -> u64 {
    adresse_mac.par_iter().map(|&x| x as u64).sum()
}

fn generate_key2(seed: &str) -> Result<Vec<u8>, SystemTrayError> {
    if seed.len() < 10 {
        return Err(SystemTrayError::new(4));
    }

    let seed = kdfwagen::kdfwagen(seed.as_bytes(), get_salt().as_bytes(), NUM_ITERATIONS);

    Ok(seed)
}


use std::sync::{Arc, Mutex};

fn insert_random_stars(mut word: Vec<u8>) -> Vec<u8> {
    let rng = Arc::new(Mutex::new(Nebula::new(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())));

    let num_stars: usize = rng.lock().unwrap().generate_bounded_number((word.len()/2) as u128, word.len() as u128).unwrap() as usize;

    // In utf-8, the '^' character is 94
    let mut stars: Vec<u8> = vec![94; num_stars];

    // Generate random indices in parallel
    let random_indices: Vec<usize> = (0..num_stars).into_par_iter()
        .map(|_| {
            let mut rng = rng.lock().unwrap();
            rng.generate_bounded_number(0, word.len() as u128).unwrap() as usize
        })
        .collect();

    // Sort indices in descending order
    let mut sorted_indices = random_indices;
    sorted_indices.par_sort_unstable_by(|a, b| b.cmp(a));

    // Insert stars at the calculated indices
    for index in sorted_indices {
        word.insert(index, stars.pop().unwrap());
    }

    word
}

fn vz_maker(val1: u64, val2:u64, seed: u64) -> Vec<u8>{
    kdfwagen(&[(val1+val2) as u8,(val1*val2) as u8, (val1%val2) as u8, seed as u8, val1.abs_diff(val2) as u8], get_salt().as_bytes(), 10)
}

pub(crate) fn encrypt3(plain_text: Vec<u8>, key1: &Vec<u8>, key2: &Vec<u8>, password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let inter = insert_random_stars(plain_text);

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


pub(crate) fn decrypt3(cipher_text: Vec<u8>, key1: &Vec<u8>, key2: &Vec<u8>, password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
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
            if let Some(col) = table[table_2d][row].iter().position(|x| x == c) {
                if characters[col] != 94 {
                    Some(characters[col])
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }).collect();

    Ok(plain_text)
}

fn xor_crypt3(input: &mut [u8], key: &[u8]) {
    input.par_iter_mut().enumerate().for_each(|(i, byte)| {
        *byte ^= key[i % key.len()];
    });
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
fn main() {
    // let plain_text = "cest moi le le grand test du matin et je à suis content";
    let plain_text = "cest moi le le grand test du matin et je à suis content éèù:;?";
    let pass = "LeMOTdePAsse34!";

    let key1 = match generate_key2(pass) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("Erreur : {}", err);
            return;
        },

    };

    // Test encrypt3
    match encrypt3(plain_text.as_bytes().to_vec(), &key1, &key1, pass) {
        Ok(encrypted) => {
            println!("Encrypted: {:?}", encrypted);


            // Test decrypt3
            match decrypt3(encrypted, &key1, &key1, pass) {
                Ok(decrypted) => {
                    println!("Decrypted: {:?}", decrypted);
                    println!("convert u8: {:?}", String::from_utf8(decrypted.clone()).unwrap());
                    if decrypted == plain_text.as_bytes().to_vec() {
                        println!("Success!");
                    } else {
                        println!("Decryption failed");
                    }
                },
                Err(e) => panic!("Decryption failed with error: {:?}", e),
            }
        }
        Err(e) => panic!("Encryption failed with error: {:?}", e),
    }
}


#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Read;
    use super::*;

    #[test]
    fn test_crypt_file(){ //still not functionning
        let _key1 = generate_key();
        let password = "bonjourcestmoi";
        let _key2 = generate_key2(password);
        let _key3 = generate_key2(password);


        // Read the content of the file
        let mut file_content = Vec::new();
        let mut file = File::open("invoicesample.pdf").unwrap();
        file.read_to_end(&mut file_content).expect("TODO: panic message");

        // Encrypt the content
        //let encrypted_content = encrypt3(file_content.clone(), &key1, &key2.unwrap(), password);
        let a = vz_maker(123456789, 368291, 567675);
        let mut encrypted_content = shift_bits(file_content.clone(), &a);
        // Write the encrypted content to the output file
        //let mut output_file = File::create("invoicesample2.pdf").unwrap();
        xor_crypt3(&mut encrypted_content, &a);
        //output_file.write_all(&encrypted_content.clone()).expect("TODO: panic message");


        //reverse process

        // Read the content of the file
        //let mut file_content2 = Vec::new();
        //let mut file = File::open("invoicesample2.pdf").unwrap();
        //file.read_to_end(&mut file_content2).expect("TODO: panic message");

        // dcrypt the content
        //let dcrypted_content = decrypt3(ac, &key1, &key3.unwrap(), password);
        xor_crypt3(&mut encrypted_content, &a);
        let dcrypted_content = unshift_bits(encrypted_content, &a);

        let copi = dcrypted_content;

        assert_eq!(copi, file_content);

        // Write the encrypted content to the output file
        //let mut output_file = File::create("invoicesample3.pdf").unwrap();
        //output_file.write_all(&copi).expect("TODO: panic message");
    }


    #[test]
    fn test_table3() {
        let size = 255;

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
        assert_ne!(salt.len(), 0);
    }


    #[test]
    fn test_generate_key() {
        let key = generate_key();

        println!("Key size : {}", key.len());
        println!("Key: {:?}", key);
        assert_ne!(key.len(), 0);
    }

    #[test]
    fn test_generate_key2() {
        let seed = "0123456789";
        let key = generate_key2(&seed).unwrap();

        println!("Key size : {}", key.len());
        println!("Key: {:?}", key);

        assert_ne!(key.len(), 0)
    }

    #[test]
    fn test_insert_random_stars() {
        let word = "Hello World!".as_bytes().to_vec();
        let word2 = insert_random_stars(word.clone());

        println!("Word: {:?}", word2);
        assert_ne!(word, word2);
    }


    #[test]
    fn test_shift_unshift_bits() {
        let original_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let shifted_data = shift_bits(original_data.clone(), &key);
        let unshifted_data = unshift_bits(shifted_data, &key);

        assert_eq!(original_data, unshifted_data);
    }
}
