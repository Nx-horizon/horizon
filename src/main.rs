mod systemtrayerror;
mod kdfwagen;
mod cryptex;
mod nebula;
mod key_transmiter;

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

/// Generates a 3-dimensional table of bytes.
///
/// # Arguments
///
/// * `size` - The size of each dimension of the table.
/// * `seed` - The seed value for shuffling the characters.
///
/// # Returns
///
/// A 3-dimensional vector containing bytes.
///
/// # Panics
///
/// This function will panic if `size` is 0.
///
/// # Examples
///
/// ```
/// let size = 10;
/// let seed = 42;
/// let table = table3(size, seed);
/// assert_eq!(table.len(), size);
/// assert_eq!(table[0].len(), size);
/// assert_eq!(table[0][0].len(), size);
/// ```
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


/// Generates a unique salt string based on system information.
///
/// # Returns
///
/// A string containing a unique salt based on system information.
///
/// # Panics
///
/// This function will panic if any of the system information queries fail.
///
/// # Examples
///
/// ```
/// let salt = get_salt();
/// println!("Generated salt: {}", salt);
/// ```
fn get_salt() -> String {
    System::name().unwrap_or("".to_string()) + &System::host_name().unwrap_or("".to_string()) + &System::os_version().unwrap_or("".to_string())  + &System::kernel_version().unwrap_or("".to_string())
}


pub fn generate_key() -> Vec<u8> {

    match get_mac_address() {
        Ok(Some(mac_address)) => {
            let mac_address_str = mac_address.to_string();
            let returner = kdfwagen(mac_address_str.as_bytes(), get_salt().as_bytes(), NUM_ITERATIONS);
            returner
        },
        Ok(None) => {
            eprintln!("No MAC address found.");
            Vec::new()
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            Vec::new()
        },
    }

}


/// Calculates the sum of the elements in a byte slice representing a MAC address.
///
/// # Arguments
///
/// * `adresse_mac` - A reference to a byte slice representing a MAC address.
///
/// # Returns
///
/// The sum of the elements in the byte slice as a `u64` value.
///
/// # Examples
///
/// ```
/// let mac_address: [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
/// let sum = addition_chiffres(&mac_address);
/// assert_eq!(sum, 0xAABBCCDDEEFF);
/// ```
fn addition_chiffres(adresse_mac: &[u8]) -> u64 {
    adresse_mac.par_iter().map(|&x| x as u64).sum()
}

/// Generates a key based on a seed string.
///
/// # Arguments
///
/// * `seed` - A reference to a seed string used for key generation.
///
/// # Returns
///
/// A result containing either the generated key as a `Vec<u8>` or a `SystemTrayError`.
///
/// # Examples
///
/// ```
/// let seed = "random_seed_string";
/// match generate_key2(seed) {
///     Ok(key) => println!("Generated key: {:?}", key),
///     Err(err) => eprintln!("Error: {}", err),
/// }
/// ```
fn generate_key2(seed: &str) -> Result<Vec<u8>, SystemTrayError> {
    if seed.len() < 10 {
        return Err(SystemTrayError::new(4));
    }
    
    let salt = get_salt();
    println!("salt: {}", salt);
    if salt.len() < 10 {
        return Err(SystemTrayError::new(10));
    }
    
    
    let seed = kdfwagen::kdfwagen(seed.as_bytes(), salt.as_bytes(), NUM_ITERATIONS);

    Ok(seed)
}


use std::sync::{Arc, Mutex};

/// Inserts random stars into a byte vector.
///
/// # Arguments
///
/// * `word` - A byte vector into which random stars will be inserted.
///
/// # Returns
///
/// A byte vector with random stars inserted.
///
/// # Examples
///
/// ```
/// let word = b"example".to_vec();
/// let word_with_stars = insert_random_stars(word);
/// println!("Word with stars: {:?}", word_with_stars);
/// ```
fn insert_random_stars(mut word: Vec<u8>) -> Vec<u8> {
    let rng = Arc::new(Mutex::new(Nebula::new(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())));

    let num_stars: usize = rng.lock().unwrap().generate_bounded_number((word.len()/2) as u128, word.len() as u128).unwrap() as usize;

    let mut stars: Vec<u8> = vec![94; num_stars];

    let random_indices: Vec<usize> = (0..num_stars).into_par_iter()
        .map(|_| {
            let mut rng = rng.lock().unwrap();
            rng.generate_bounded_number(0, word.len() as u128).unwrap() as usize
        })
        .collect();

    let mut sorted_indices = random_indices;
    sorted_indices.par_sort_unstable_by(|a, b| b.cmp(a));

    for index in sorted_indices {
        word.insert(index, stars.pop().unwrap());
    }

    word
}

/// Creates a vector based on arithmetic operations and a seed.
///
/// # Arguments
///
/// * `val1` - The first value used for arithmetic operations.
/// * `val2` - The second value used for arithmetic operations.
/// * `seed` - The seed value used for vector generation.
///
/// # Returns
///
/// A vector of bytes generated based on arithmetic operations and the seed.
///
/// # Examples
///
/// ```
/// let val1 = 10;
/// let val2 = 20;
/// let seed = 42;
/// let result = vz_maker(val1, val2, seed);
/// println!("Resulting vector: {:?}", result);
/// ```
fn vz_maker(val1: u64, val2:u64, seed: u64) -> Vec<u8>{
    kdfwagen(&[(val1+val2) as u8,(val1*val2) as u8, (val1%val2) as u8, seed as u8, val1.abs_diff(val2) as u8], get_salt().as_bytes(), 10)
}


/// Encrypts plain text using a double-key encryption scheme.
///
/// # Arguments
///
/// * `plain_text` - The plain text to encrypt as a vector of bytes.
/// * `key1` - The first encryption key as a reference to a vector of bytes.
/// * `key2` - The second encryption key as a reference to a vector of bytes.
/// * `password` - The password used for additional encryption.
///
/// # Returns
///
/// A result containing either the encrypted cipher text as a vector of bytes or an error.
///
/// # Examples
///
/// ```
/// let plain_text = b"example text".to_vec();
/// let key1 = b"key1".to_vec();
/// let key2 = b"key2".to_vec();
/// let password = "password";
///
/// match encrypt3(plain_text, &key1, &key2, password) {
///     Ok(cipher_text) => println!("Cipher text: {:?}", cipher_text),
///     Err(err) => eprintln!("Error: {}", err),
/// }
/// ```
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

/// Decrypts cipher text encrypted using a double-key encryption scheme.
///
/// # Arguments
///
/// * `cipher_text` - The cipher text to decrypt as a vector of bytes.
/// * `key1` - The first encryption key as a reference to a vector of bytes.
/// * `key2` - The second encryption key as a reference to a vector of bytes.
/// * `password` - The password used for additional decryption.
///
/// # Returns
///
/// A result containing either the decrypted plain text as a vector of bytes or an error.
///
/// # Examples
///
/// ```
/// let cipher_text = vec![/* insert cipher text here */];
/// let key1 = b"key1".to_vec();
/// let key2 = b"key2".to_vec();
/// let password = "password";
///
/// match decrypt3(cipher_text, &key1, &key2, password) {
///     Ok(plain_text) => println!("Plain text: {:?}", plain_text),
///     Err(err) => eprintln!("Error: {}", err),
/// }
/// ```
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

/// Performs XOR encryption/decryption on a byte slice using a key.
///
/// # Arguments
///
/// * `input` - A mutable reference to the byte slice to be encrypted/decrypted.
/// * `key` - The key used for encryption/decryption as a byte slice.
///
/// # Examples
///
/// ```
/// let mut data = vec![/* insert data here */];
/// let key = vec![/* insert key here */];
///
/// xor_crypt3(&mut data, &key);
///
/// // At this point, `data` contains the encrypted or decrypted result.
/// ```
fn xor_crypt3(input: &mut [u8], key: &[u8]) {
    input.par_iter_mut().enumerate().for_each(|(i, byte)| {
        *byte ^= key[i % key.len()];
    });
}

/// Performs bit shifting on a byte vector based on a key.
///
/// # Arguments
///
/// * `cipher_text` - The byte vector to be shifted.
/// * `key` - The key used for bit shifting as a byte slice.
///
/// # Returns
///
/// A byte vector containing the result of the bit shifting operation.
///
/// # Examples
///
/// ```
/// let cipher_text = vec![/* insert cipher text here */];
/// let key = vec![/* insert key here */];
///
/// let shifted_text = shift_bits(cipher_text, &key);
///
/// // At this point, `shifted_text` contains the result of bit shifting.
/// ```
pub fn shift_bits(cipher_text: Vec<u8>, key: &[u8]) -> Vec<u8> {
    cipher_text.par_iter().enumerate().map(|(i, &byte)| {
        let shift_amount = key[i % key.len()];
        
        byte.rotate_left(shift_amount as u32)
    }).collect::<Vec<u8>>()
}

/// Reverses the bit shifting operation performed by the `shift_bits` function.
///
/// # Arguments
///
/// * `cipher_text` - The byte vector to be unshifted.
/// * `key` - The key used for bit shifting as a byte slice.
///
/// # Returns
///
/// A byte vector containing the result of the reverse bit shifting operation.
///
/// # Examples
///
/// ```
/// let cipher_text = vec![/* insert cipher text here */];
/// let key = vec![/* insert key here */];
///
/// let unshifted_text = unshift_bits(cipher_text, &key);
///
/// // At this point, `unshifted_text` contains the result of reverse bit shifting.
/// ```
pub fn unshift_bits(cipher_text: Vec<u8>, key: &[u8]) -> Vec<u8> {
    cipher_text.par_iter().enumerate().map(|(i, &byte)| {
        let shift_amount = key[i % key.len()];
        
        byte.rotate_right(shift_amount as u32)
    }).collect::<Vec<u8>>() // Collect into a Vec<u8>
}

/// The entry point of the program.
///
/// This function demonstrates the usage of the `encrypt3` and `decrypt3` functions with a sample plain text and password.
///
/// # Examples
///
/// ```
/// // let plain_text = "cest moi le le grand test du matin et je à suis content";
/// let plain_text = "cest moi le le grand test du matin et je à suis content éèù:;?";
/// let pass = "LeMOTdePAsse34!";
///
/// let key1 = match generate_key2(pass) {
///     Ok(key) => key,
///     Err(err) => {
///         eprintln!("Error: {}", err);
///         return;
///     },
/// };
///
/// // Test encrypt3
/// match encrypt3(plain_text.as_bytes().to_vec(), &key1, &key1, pass) {
///     Ok(encrypted) => {
///         println!("Encrypted: {:?}", encrypted);
///
///         // Test decrypt3
///         match decrypt3(encrypted.clone(), &key1, &key1, pass) {
///             Ok(decrypted) => {
///                 println!("Decrypted: {:?}", decrypted);
///                 println!("Converted to string: {:?}", String::from_utf8(decrypted.clone()).unwrap());
///                 if decrypted == plain_text.as_bytes().to_vec() {
///                     println!("Success!");
///                 } else {
///                     println!("Decryption failed");
///                 }
///             },
///             Err(e) => panic!("Decryption failed with error: {:?}", e),
///         }
///     }
///     Err(e) => panic!("Encryption failed with error: {:?}", e),
/// }
/// ```
fn main() {
    let plain_text = "cest moi le le grand test du matin et je à suis content éèù:;?";
    let pass = "LeMOTdePAsse34!";

    let key1 = match generate_key2(pass) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("Erreur : {}", err);
            return;
        },

    };

    match encrypt3(plain_text.as_bytes().to_vec(), &key1, &key1, pass) {
        Ok(encrypted) => {
            println!("Encrypted: {:?}", encrypted);


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
    use std::io::{Read, Write};
    use crate::cryptex::{decrypt_file, encrypt_file};
    use super::*;

    #[test]
/// Tests file encryption and decryption.
///
/// This function demonstrates the process of encrypting and decrypting the content of a file.
/// It reads the content of a file, encrypts it using the `encrypt_file` function, then decrypts it back using the `decrypt_file` function.
/// Finally, it verifies that the decrypted content matches the original content of the file.
///
/// # Note
///
/// This function is meant for testing purposes and should be adapted or extended for actual use cases.
///
/// # Examples
///
/// ```
/// // Execute the test for file encryption and decryption
/// test_crypt_file();
/// ```
    fn test_crypt_file(){
        let key1 = generate_key();
        let password = "bonjourcestmoi";
        let key2 = generate_key2(password);
        let key3 = generate_key2(password);


        let mut file_content = Vec::new();
        let mut file = File::open("invoicesample.pdf").unwrap();
        file.read_to_end(&mut file_content).expect("TODO: panic message");

        let encrypted_content = encrypt_file(file_content.clone(), &key1, &key2.unwrap(), password);


        let dcrypted_content = decrypt_file(encrypted_content.unwrap(), &key1, &key3.unwrap(), password);
        let a = dcrypted_content.unwrap();
        assert_eq!(a.clone(), file_content);

        let mut output_file = File::create("invoicesample3.pdf").unwrap();
        output_file.write_all(&a.clone()).expect("TODO: panic message");
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
        let key = generate_key2(seed).unwrap();

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

    #[test]
    fn test_sum_vec() {
        let password = "test_password";
        let password2 = "test_passwordergt";
        let salt = get_salt();
        let num_iterations = 10;

        // Call the kdfwagen function
        let result_vec = kdfwagen(password.as_bytes(), salt.as_bytes(), num_iterations);
        let vector_2 = kdfwagen(password2.as_bytes(), salt.as_bytes(), num_iterations);

        // Calculate the sum of the vector elements
        let sum: u128 = result_vec.iter().map(|&x| x as u128).sum();
        let sum2: u128 = vector_2.iter().map(|&x| x as u128).sum();

        // Check if the sum is as expected (replace `expected_sum` with the actual expected sum)
        let expected_sum: u128 = 67309; // Replace 0 with the actual expected sum
        assert_ne!(sum+sum2, expected_sum, "The sum of the vector elements is not as expected");

        let mut rng = Nebula::new(sum+sum2);
        let random_bytes = rng.generate_random_number();
        println!("{:?}", random_bytes);
    }
}
