use hashbrown::HashMap;
use std::error::Error;
use rayon::prelude::*;
use secrecy::{ExposeSecret, Secret};
use crate::{addition_chiffres, get_salt, KEY_LENGTH, nebula, NUM_ITERATIONS, shift_bits, table3, unshift_bits, vz_maker, xor_crypt3};
use crate::kdfwagen::kdfwagen;


/// This function encrypts the content of a file using two secret keys and a password.
///
/// # Arguments
///
/// * `plain_text` - The content of the file to be encrypted.
/// * `key1` - A secret key used for encryption.
/// * `key2` - Another secret key used for encryption.
/// * `password` - The password used for additional encryption.
///
/// # Returns
///
/// A `Result` containing the encrypted content of the file, or an error if encryption fails.
///
/// # Errors
///
/// Returns an error if encryption fails for any reason.
///
/// # Example
///
/// ```
/// use your_crate::encrypt_file;
///
/// // Read the content of the file to be encrypted
/// let plain_text = std::fs::read("file.txt").expect("Failed to read file");
///
/// // Provide secret keys and a password
/// let key1 = Secret::new(vec![1, 2, 3]);
/// let key2 = Secret::new(vec![4, 5, 6]);
/// let password = "my_password";
///
/// // Encrypt the content of the file
/// let encrypted = encrypt_file(plain_text, &key1, &key2, password);
///
/// match encrypted {
///     Ok(encrypted_content) => {
///         // Write the encrypted content to another file
///         std::fs::write("encrypted_file.txt", encrypted_content).expect("Failed to write file");
///         println!("File encrypted successfully");
///     }
///     Err(err) => {
///         eprintln!("Error occurred during encryption: {:?}", err);
///     }
/// }
/// ```
pub(crate) fn encrypt_file(plain_text: Vec<u8>, key1: &Secret<Vec<u8>>, key2: &Secret<Vec<u8>>, password: &str) -> Result<Vec<u8>, Box<dyn Error>> {

    let key1 = key1.expose_secret();
    let key2 = key2.expose_secret();

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

    let mut cipher_text: Vec<_> = plain_text.par_iter().enumerate().filter_map(|(i, c)| {
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

    xor_crypt3(&mut cipher_text, kdfwagen(password.as_bytes(), get_salt().as_bytes(), NUM_ITERATIONS));
    let vz = vz_maker(val1, val2, seed);

    Ok(shift_bits(cipher_text, vz))
}


/// Decrypts the content of a file.
///
/// This function decrypts the content of a file using two secret keys and a password.
///
/// # Arguments
///
/// * `cipher_text` - The encrypted content of the file to be decrypted.
/// * `key1` - A secret key used for decryption.
/// * `key2` - Another secret key used for decryption.
/// * `password` - The password used for decryption.
///
/// # Returns
///
/// A `Result` containing the decrypted content of the file, or an error if decryption fails.
///
/// # Errors
///
/// Returns an error if decryption fails for any reason.
///
/// # Example
///
/// ```
/// use your_crate::decrypt_file;
///
/// // Read the encrypted content of the file
/// let encrypted_content = std::fs::read("encrypted_file.txt").expect("Failed to read file");
///
/// // Provide secret keys and a password
/// let key1 = Secret::new(vec![1, 2, 3]);
/// let key2 = Secret::new(vec![4, 5, 6]);
/// let password = "my_password";
///
/// // Decrypt the content of the file
/// let decrypted = decrypt_file(encrypted_content, &key1, &key2, password);
///
/// match decrypted {
///     Ok(decrypted_content) => {
///         // Write the decrypted content to another file
///         std::fs::write("decrypted_file.txt", decrypted_content).expect("Failed to write file");
///         println!("File decrypted successfully");
///     }
///     Err(err) => {
///         eprintln!("Error occurred during decryption: {:?}", err);
///     }
/// }
/// ```
pub(crate) fn decrypt_file(cipher_text: Vec<u8>, key1: &Secret<Vec<u8>>, key2: &Secret<Vec<u8>>, password: &str) -> Result<Vec<u8>, Box<dyn Error>> {


    let key1 = key1.expose_secret();
    let key2 = key2.expose_secret();

    let val1 = addition_chiffres(key2);
    let val2 = addition_chiffres(key1);

    let seed = val2 * val1 ;

    let mut characters: Vec<u8> = (0..=255).collect();
    nebula::seeded_shuffle(&mut characters, seed as usize);

    let table = table3(256, seed);

    let table_len = 256;

    let vz = vz_maker(val1, val2, seed);
    let mut cipher_text = unshift_bits(cipher_text, vz);
    xor_crypt3(&mut cipher_text, kdfwagen(password.as_bytes(), get_salt().as_bytes(), NUM_ITERATIONS));

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

