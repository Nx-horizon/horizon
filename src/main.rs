use std::error::Error;
use argon2::Argon2;

use hashbrown::HashMap;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use rand::seq::SliceRandom;
use rayon::prelude::*;
use secrecy::{ExposeSecret, Secret};
use sysinfo::System;

use crate::cryptex::{decrypt_file, encrypt_file};
use crate::systemtrayerror::SystemTrayError;

mod systemtrayerror;
mod kdfwagen;
mod cryptex;
mod nebula;

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

    seeded_shuffle(&mut characters, seed as usize);

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

fn seeded_shuffle<T>(items: &mut [T], seed: usize) {

    let mut rng = StdRng::seed_from_u64(seed as u64);

    items.shuffle(&mut rng);
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
fn addition_chiffres(adresse_mac: &Vec<u8>) -> u64 {
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
fn generate_key2(seed: &str) -> Result<Secret<Vec<u8>>, SystemTrayError> {
    if seed.len() < 10 {
        return Err(SystemTrayError::new(4));
    }

    let salt = get_salt();
    if salt.len() < 10 {
        return Err(SystemTrayError::new(10));
    }


    let seed = gene3(seed.as_bytes());

    Ok(seed)
}

fn gene3(seed: &[u8]) -> Secret<Vec<u8>> {
    let mut output_key_material = vec![0u8; KEY_LENGTH];

    // Call hash_password_into and handle the result
    Argon2::default()
        .hash_password_into(seed, get_salt().as_ref(), &mut output_key_material)
        .expect("Hashing failed"); // Handle the error appropriately

    // Wrap the output key material in a Secret and return it
    Secret::new(output_key_material)
}


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
    // Générer un nombre aléatoire entre word.len() / 2 et word.len()
    let num_null_bits: usize = {
        let mut rng = rand::thread_rng();
        let lower_bound = (word.len() / 2) as u128;
        let upper_bound = word.len() as u128;
        rng.gen_range(lower_bound..upper_bound) as usize
    };

    // Générer tous les indices aléatoires en une seule opération
    let random_indices: Vec<usize> = (0..num_null_bits)
        .into_par_iter()
        .map(|_| {
            let mut rng = rand::thread_rng(); // Créer une nouvelle instance de ThreadRng
            rng.gen_range(0..word.len()) // Utilisation de gen_range
        })
        .collect();

    // Trier les indices en ordre décroissant pour éviter de décaler les indices
    let mut sorted_indices = random_indices;
    sorted_indices.par_sort_unstable_by(|a, b| b.cmp(a));

    // Insérer les bits nuls directement
    for index in sorted_indices {
        word.insert(index, 0); // Insérer le bit 0 (0x00)
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
fn vz_maker(val1: u64, val2:u64, seed: u64) -> Secret<Vec<u8>> {
    gene3(&[(val1+val2) as u8,(val1%val2) as u8, seed as u8, val1.abs_diff(val2) as u8,  val1.wrapping_mul(val2) as u8])
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

pub(crate) fn encrypt3(plain_text: Vec<u8>, key1: &Secret<Vec<u8>>, key2: &Secret<Vec<u8>>) -> Result<Vec<u8>, Box<dyn Error>> {
    let inter = insert_random_stars(plain_text);

    let key1 = key1.expose_secret();
    let key2 = key2.expose_secret();

    let val1 = addition_chiffres(key2);
    let val2 = addition_chiffres(key1);
    let seed = val2 * val1;

    // Préparation de la table de caractères
    let mut characters: Vec<u8> = (0..=255).collect();
    let table = table3(256, seed);
    seeded_shuffle(&mut characters, seed as usize);

    // Création d'un HashMap pour les positions des caractères sans utiliser enumerate
    let char_positions: HashMap<u8, usize> = (0..characters.len())
        .into_par_iter()
        .map(|i| (characters[i], i))
        .collect();

    let key1_chars: Vec<usize> = key1.par_iter().map(|&c| c as usize % 256).collect();
    let key2_chars: Vec<usize> = key2.par_iter().map(|&c| c as usize % 256).collect();
    let key1_len = KEY_LENGTH;
    let key2_len = KEY_LENGTH;

    // Pré-allocation du vecteur de texte chiffré
    let mut cipher_text: Vec<u8> = (0..inter.len())
        .into_par_iter()
        .filter_map(|i| {
            let c = inter[i];
            let table_2d = key1_chars[i % key1_len] % 256;
            let row = key2_chars[i % key2_len] % 256;

            if let Some(&col) = char_positions.get(&c) {
                if table_2d < table.len() && row < table[table_2d].len() {
                    Some(table[table_2d][row][col])
                } else {
                    println!("Character '{}' not found in character set", c);
                    None
                }
            } else {
                None
            }
        })
        .collect();

    // Appliquer le XOR avec la clé
    let mut key_clone = key1.clone();
    key_clone.rotate_left(seed as usize % 64);
    xor_crypt3(&mut cipher_text, &key_clone);

    let vz = vz_maker(val1, val2, seed);
    Ok(shift_bits(cipher_text, vz))
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
pub(crate) fn decrypt3(cipher_text: Vec<u8>, key1: &Secret<Vec<u8>>, key2: &Secret<Vec<u8>>) -> Result<Vec<u8>, Box<dyn Error>> {
    let key1 = key1.expose_secret();
    let key2 = key2.expose_secret();

    let val1 = addition_chiffres(key2);
    let val2 = addition_chiffres(key1);
    let seed = val2 * val1;

    let mut characters: Vec<u8> = (0..=255).collect();
    seeded_shuffle(&mut characters, seed as usize);

    let table = table3(256, seed);
    let table_len = 256;

    let vz = vz_maker(val1, val2, seed);
    let mut cipher_text = unshift_bits(cipher_text, vz);

    // Appliquer le XOR avec la clé
    let mut key_clone = key1.clone();
    key_clone.rotate_left(seed as usize % 64);
    xor_crypt3(&mut cipher_text, &key_clone);

    let key1_chars: Vec<usize> = key1.par_iter().map(|&c| c as usize % 256).collect();
    let key2_chars: Vec<usize> = key2.par_iter().map(|&c| c as usize % 256).collect();
    let key1_len = KEY_LENGTH;
    let key2_len = KEY_LENGTH;

    // Pré-allocation du vecteur de texte en clair
    let plain_text: Vec<u8> = (0..cipher_text.len())
        .into_par_iter()
        .filter_map(|i| {
            let c = cipher_text[i];
            let table_2d = key1_chars[i % key1_len] % table_len;
            let row = key2_chars[i % key2_len] % table_len;

            if table_2d < table_len && row < table[table_2d].len() {
                if let Some(col) = table[table_2d][row].iter().position(|&x| x == c) {
                    if characters[col] != 0 {
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
        })
        .collect();

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
pub fn shift_bits(cipher_text: Vec<u8>, key: Secret<Vec<u8>>) -> Vec<u8> {
    let key = key.expose_secret();
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
pub fn unshift_bits(cipher_text: Vec<u8>, key: Secret<Vec<u8>>) -> Vec<u8> {
    let key = key.expose_secret();
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
    // Données originales et mot de passe
    let original_data = "ce soir je sors ne t'inquiète pas je rentre bientôt";
    let pass = "LeMOTdePAsse34!";
    const ROUND: usize = 6;

    let key1 = gene3(pass.as_bytes());

    // Génération de la liste de clés aléatoires
    let mut rng = rand::thread_rng();
    let liste: Vec<String> = (0..ROUND)
        .map(|_| rng.gen::<u64>().to_string()) // Générer un nombre aléatoire de type u64
        .collect();

    let mut chif = original_data.as_bytes().to_vec();

    // Chiffrement
    for (index, element) in liste.iter().enumerate() {
        let key2 = gene3(element.as_bytes());
        chif = if index == 0 {
            encrypt3(chif, &key1, &key2).unwrap()
        } else {
            encrypt_file(chif, &key1, &key2).unwrap()
        };
        println!(" {} Chiffré : {}", index, String::from_utf8_lossy(&chif));
    }

    println!("-----------------------------------------");

    // Déchiffrement
    for (index, element) in liste.iter().enumerate().rev() {
        let key2 = gene3(element.as_bytes());
        chif = if index == 0 {
            decrypt3(chif, &key1, &key2).unwrap()
        } else {
            decrypt_file(chif, &key1, &key2).unwrap()
        };
        println!("{} déChiffré : {}", index, String::from_utf8_lossy(&chif));
    }

    assert_eq!(original_data, String::from_utf8_lossy(&chif));
}



#[cfg(test)]
mod tests {
    use std::fs::File;

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
        //let password = "bonjourcestmoi";
        //let key1 = generate_key2(password);
        //let key2 = generate_key2(password);
        //let key3 = generate_key2(password);


        //let mut file_content = Vec::new();
        //let mut file = File::open("invoicesample.pdf").unwrap();
        //file.read_to_end(&mut file_content).expect("TODO: panic message");

        //let encrypted_content = encrypt_file(file_content.clone(), &key1.unwrap(), &key2.unwrap());

        //let b = encrypted_content.unwrap();


        //let dcrypted_content = decrypt_file(b, &key1.unwrap(), &key3.unwrap());
        //let a = dcrypted_content.unwrap();
        //assert_eq!(a.clone(), file_content);
    }

    #[test]
    fn test_table3() {
        let size = 255;

        let table = table3(size, 123456789);

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
    fn test_speed_table(){
        let size = 255;
        table3(size, 123456789);
    }

    #[test]
    fn test_get_salt() {
        let salt = get_salt();
        assert_ne!(salt.len(), 0);
    }

    #[test]
    fn test_generate_key2() {
        let seed = "0123456789";
        let key = generate_key2(seed).unwrap();


        assert_ne!(key.expose_secret().len(), 0)
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
        let original_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10,1, 2, 3, 4, 5, 6, 7, 8, 9, 10,1, 2, 3, 4, 5, 6, 7, 8, 9, 10,1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let shifted_data = shift_bits(original_data.clone(), Secret::new(key.clone()));
        let unshifted_data = unshift_bits(shifted_data, Secret::new(key));

        assert_eq!(original_data, unshifted_data);
    }


    #[test]
    fn safe_crypt() {
        // Données originales et mot de passe
        let original_data = "ce soir je sors ne t'inquiète pas je rentre bientôt";
        let pass = "LeMOTdePAsse34!";

        const ROUND: usize = 8;

        // Génération de la clé principale
        let key1 = match generate_key2(pass) {
            Ok(key) => key,
            Err(err) => {
                eprintln!("Erreur : {}", err);
                return;
            },
        };

        // Génération de la liste de clés aléatoires
        let mut rng = rand::thread_rng();
        let liste: Vec<String> = (0..ROUND)
            .map(|_| rng.gen::<u64>().to_string()) // Générer un nombre aléatoire de type u64
            .collect();

        let mut chif = original_data.as_bytes().to_vec();

        for (index, element) in liste.iter().enumerate() { //TODO modifier key1 rotation par rapport à key 2
            let key2 = generate_key2(element).unwrap();
            chif = if index < 1 {
                encrypt3(chif, &key1, &key2).unwrap()
            } else {
                encrypt_file(chif, &key1, &key2).unwrap()
            };

            println!(" {} Chiffré : {}",index, String::from_utf8_lossy(&chif));
        }

        println!("-----------------------------------------");

        for (index, element) in liste.iter().enumerate().rev() {
            let key2 = generate_key2(element).unwrap();
            chif = if index < 1 {
                decrypt3(chif, &key1, &key2).unwrap()
            } else {
                decrypt_file(chif, &key1, &key2).unwrap()
            };

            println!("{} déChiffré : {}",index, String::from_utf8_lossy(&chif));
        }

        assert_eq!(original_data, String::from_utf8_lossy(&chif));
    }

    use std::io::Write;
    use std::io::{BufRead, BufReader};

    #[test]
    fn test_duplicate_lines() -> std::io::Result<()> {
        // Ouvrir le fichier output.txt en lecture
        let input_file = File::open("output.txt")?;
        let reader = BufReader::new(input_file);

        // Ouvrir le fichier tri.txt en écriture
        let mut output_file = File::create("tri.txt")?;

        // Lire toutes les lignes du fichier
        let lines: Vec<String> = reader.lines().collect::<Result<_, _>>()?;

        // Parcourir chaque ligne du fichier
        for i in 0..lines.len() {
            for j in i + 1..lines.len() {
                // Si deux lignes sont identiques
                if lines[i] == lines[j] {
                    // Écrire la ligne dans le fichier tri.txt
                    writeln!(output_file, "{}", lines[i])?;
                }
            }
        }

        Ok(())
    }

    #[test]
    fn test_gene3() {
        let seed = b"test_seed"; // Exemple de graine
        let secret = gene3(seed);

        // Vérifier que le matériel de clé de sortie a la bonne longueur
        assert_eq!(secret.expose_secret().len(), KEY_LENGTH);

        // Vous pouvez également vérifier que le matériel de clé de sortie n'est pas vide
        assert!(!secret.expose_secret().is_empty());
    }

    #[test]
    fn test_gene3_different_seeds() {
        let seed1 = b"seed_one";
        let seed2 = b"seed_two";

        let secret1 = gene3(seed1);
        let secret2 = gene3(seed2);

        // Vérifier que les résultats sont différents pour des graines différentes
        assert_ne!(secret1.expose_secret(), secret2.expose_secret());
    }

}
