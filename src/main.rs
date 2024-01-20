mod systemtrayerror;
mod kdfwagen;
mod cryptex;
mod prng;

use std::collections::hash_map::DefaultHasher;
use rand::Rng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rand::prelude::*;
use mac_address::get_mac_address;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use rand::rngs::OsRng;
use rayon::prelude::*;
use crate::kdfwagen::kdfwagen;
use crate::systemtrayerror::SystemTrayError;

//v 0.5.12
/// Generates a 3D table of char based on the input character set and a provided seed.
///
/// # Parameters
///
/// - `characters`: A string representing the set of characters used to populate the table.
/// - `seed`: A 64-bit unsigned integer serving as the seed for the randomization process.
///
/// # Returns
///
/// Returns a 3D vector representing the table of characters, where each dimension is shuffled independently.
///
fn table2(characters: &str, seed: u64) -> Vec<Vec<Vec<char>>> {
    let len = characters.len();
    let mut chars: Vec<char> = characters.chars().collect();
    let mut rng = StdRng::seed_from_u64(seed);
    chars.shuffle(&mut rng);

    (0..len).into_par_iter().map(|i| {
        (0..len).into_par_iter().map(|j| {
            (0..len).into_par_iter().map(|k| {
                let idx = (i + j + k) % len;
                chars[idx]
            }).collect::<Vec<char>>()
        }).collect::<Vec<Vec<char>>>()
    }).collect::<Vec<Vec<Vec<char>>>>()
}

/// Generates a unique salt string by concatenating the current username, hostname, and
/// distribution information.
///
/// The function uses the `whoami` crate to retrieve the current username, hostname, and
/// distribution information. It concatenates these values to create a unique salt string.
///
/// # Returns
///
/// A `String` representing the unique salt generated from the current username, hostname, and
/// distribution information.
///
/// # Examples
///
/// ```
/// use your_crate_name::get_salt;
///
/// let salt = get_salt();
///
/// println!("Generated Salt: {}", salt);
/// ```
fn get_salt() -> String {
    whoami::username() + &whoami::hostname() + &whoami::distro()
}

/// Generate stable indices for transposition based on a specified shift.
///
/// This function generates a vector of indices that can be used for stable transposition
/// of characters in a word. The stability is achieved by hashing each index and sorting
/// the indices based on their hash values. The shift value determines the number of positions
/// each index is shifted cyclically after sorting.
///
/// # Arguments
///
/// * `word_len` - The length of the word for which indices are generated.
/// * `shift` - The number of positions to shift the sorted indices cyclically.
///
/// # Returns
///
/// * `Vec<usize>` - A vector of stable indices suitable for transposition.
///
/// # Examples
///
/// ```
/// let indices = stable_indices(5, 2);
/// assert_eq!(indices, vec![0, 3, 1, 4, 2]);
/// ```
fn stable_indices(word_len: usize, shift: usize) -> Vec<usize> {
    let mut indices: Vec<usize> = (0..word_len).collect();

    indices.sort_unstable_by(|&a, &b| {
        let mut hasher = DefaultHasher::new();
        a.hash(&mut hasher);
        let hash_a = hasher.finish();

        let mut hasher = DefaultHasher::new();
        b.hash(&mut hasher);
        let hash_b = hasher.finish();

        hash_a.cmp(&hash_b)
    });

    let shifted_indices: Vec<usize> = indices.into_iter().cycle().skip(shift).take(word_len).collect();

    shifted_indices
}


/// Transpose characters in a word based on a specified shift.
///
/// This function takes a word (string) and a shift value. It transposes characters
/// in the word by shifting their positions. The shift is performed in a stable manner
/// using a helper function `stable_indices`. If the word is empty or if the shift
/// value is greater than or equal to the word length, the function returns `None`.
///
/// # Arguments
///
/// * `word` - A string representing the word whose characters will be transposed.
/// * `shift` - The number of positions to shift the characters in the word.
///
/// # Returns
///
/// * `Some(String)` - A new string representing the transposed word.
/// * `None` - If the word is empty or if the shift value is out of bounds.
///
/// # Examples
///
/// ```
/// let result = transpose("hello", 2);
/// assert_eq!(result, Some("llohe".to_string()));
/// ```
fn transpose(word: &str, shift: usize) -> Option<String> {
    let word_chars: Vec<char> = word.chars().collect();
    let word_len = word_chars.len();

    if word_len == 0 || shift >= word_len {
        return None;
    }

    let indices = stable_indices(word_len, shift);

    let output: String = indices.par_iter()
        .map(|&i| word_chars[i])
        .collect();

    Some(output)
}
/// Generates a key using the machine's MAC address and a key derivation function (KDF).
///
/// # Returns
///
/// Returns the generated key as a hexadecimal string.
///
/// # Examples
///
/// ```rust
/// let key = generate_key();
/// println!("Generated Key: {}", key);
/// ```
pub fn generate_key() -> String {
    let returner = match get_mac_address() {
        Ok(Some(mac_address)) => {
            let mac_address_str = mac_address.to_string();
            let returner = kdfwagen(mac_address_str.as_bytes(), get_salt().as_bytes(), 30);
            hex::encode(returner)
        },
        Ok(None) => {
            println!("No MAC address found.");
            String::new()
        },
        Err(e) => {
            println!("Error: {}", e);
            String::new()
        },
    };

    returner
}
/// Calculates the sum of digits in a given MAC address string.
///
/// # Parameters
///
/// - `adresse_mac`: A string representing the MAC address from which the sum of digits will be calculated.
///
/// # Returns
///
/// Returns the sum of digits as a 32-bit unsigned integer.
///
/// # Examples
///
/// ```rust
/// let mac_address = "12:34:56:78:9A:BC";
/// let sum = addition_chiffres(mac_address);
/// println!("Sum of digits: {}", sum);
/// ```
fn addition_chiffres(adresse_mac: &str) -> u32 {
    adresse_mac
        .chars()
        .filter_map(|c| c.to_digit(10))
        .sum()
}


/// Generates a key using the provided seed and a key derivation function (KDF).
///
/// # Parameters
///
/// - `seed`: A string serving as the seed for key generation. It should be at least 10 characters long.
///
/// # Returns
///
/// Returns the generated key as a hexadecimal string on success. If the seed is less than 10 characters, returns an error of type `SystemTrayError`.
///
/// # Errors
///
/// Returns a `SystemTrayError` with code 4 if the provided seed is less than 10 characters.
///
/// # Examples
///
/// ```rust
/// match generate_key2("mysecureseed") {
///     Ok(key) => {
///         println!("Generated Key: {}", key);
///     },
///     Err(err) => {
///         println!("Error: {}", err);
///     },
/// }
/// ```
fn generate_key2(seed: &str) -> Result<String, SystemTrayError> {
    if seed.len() < 10 {
        return Err(SystemTrayError::new(4));
    }

    let seed = kdfwagen::kdfwagen(seed.as_bytes(), get_salt().as_bytes(), 30); //change salt by unique pc id

    Ok(hex::encode(seed))
}


/// Inserts a random number of caret (^) characters (stars) into the given word at random positions.
///
/// # Parameters
///
/// - `word`: A string representing the word into which random stars will be inserted.
///
/// # Returns
///
/// Returns a new string with a random number of stars (^) inserted at random positions within the original word.
///
/// # Examples
///
/// ```rust
/// let original_word = "example";
/// let word_with_stars = insert_random_stars(original_word);
/// println!("Word with Stars: {}", word_with_stars);
/// ```
fn insert_random_stars(word: &str) -> String {
    let mut rng = OsRng;
    let num_stars = rng.gen_range(word.len()/2..word.len()*2);
    let mut word_chars: Vec<char> = word.chars().collect();
    let mut stars: Vec<char> = vec!['^'; num_stars];
    let mut indices: Vec<usize> = (0..=word_chars.len()).collect();
    indices.shuffle(&mut rng);

    for index in indices.into_iter().take(num_stars) {
        word_chars.insert(index, stars.pop().unwrap());
    }

    word_chars.into_iter().collect()
}
/// Encrypts a plain text using a custom encryption algorithm based on keys, character set, and a password.
///
/// # Parameters
///
/// - `plain_text`: The plain text to be encrypted.
/// - `key1`: The first encryption key.
/// - `key2`: The second encryption key.
/// - `characters`: A string representing the set of characters used in the encryption.
/// - `password`: A password used in the encryption process.
///
/// # Returns
///
/// Returns the encrypted cipher text as a vector of unsigned 8-bit integers on success. Returns a `SystemTrayError` on failure.
///
/// # Errors
///
/// Returns a `SystemTrayError` with code 1 if an invalid table position is encountered during encryption.
/// Returns a `SystemTrayError` with code 5 if there is an issue extracting characters from `key1` or `key2`.
/// Returns a `SystemTrayError` with code 6 if a character in the plain text is not found in the character set.
///
/// # Examples
///
/// ```rust
/// let plain_text = "hello";
/// let key1 = "key1";
/// let key2 = "key2";
/// let characters = "abcdefghijklmnopqrstuvwxyz";
/// let password = "securepassword";
/// match encrypt(plain_text, key1, key2, characters, password) {
///     Ok(cipher_text) => {
///         println!("Cipher Text: {:?}", cipher_text);
///     },
///     Err(err) => {
///         println!("Error: {}", err);
///     },
/// }
/// ```
pub(crate) fn encrypt(plain_text: &str, key1: &str, key2: &str, characters: &str, password: &str) -> Result<Vec<u8>, SystemTrayError> {
    let plain_text_with_stars = insert_random_stars(plain_text);

    let val1 = addition_chiffres(key2);
    let val2 = addition_chiffres(key1);

    let seed = (val1 * val2) as u64;
    let table = table2(characters, seed);
    let mut char_positions = HashMap::with_capacity(characters.len());
    characters.chars().enumerate().for_each(|(i, c)| {
        char_positions.insert(c, i);
    });

    let mut cipher_text = String::with_capacity(plain_text_with_stars.len());

    for (i, c) in plain_text_with_stars.chars().enumerate() {
        let table_2d = key1.chars().nth(i % key1.len()).ok_or(SystemTrayError::new(5))? as usize % characters.len();
        let row = key2.chars().nth(i % key2.len()).ok_or(SystemTrayError::new(5))? as usize % characters.len();

        let col = *char_positions.get(&c).ok_or(SystemTrayError::new(6))? % characters.len();

        if table_2d < table.len() && row < table[table_2d].len() && col < table[table_2d][row].len() {
            cipher_text.push(table[table_2d][row][col]);
        } else {
            return Err(SystemTrayError::new(1));
        }
    }
    let xor = xor_crypt(&kdfwagen(password.as_bytes(), get_salt().as_bytes(), 30), cipher_text.as_bytes());

    let vz = kdfwagen(&[(val1+val2) as u8,(val1*val2) as u8, (val1%val2) as u8,  seed as u8], get_salt().as_bytes(), 10);
    Ok(shift_bits(xor, &vz))
}
/// Decrypts a cipher text using a custom decryption algorithm based on keys, character set, and a password.
///
/// # Parameters
///
/// - `cipher_text`: The cipher text to be decrypted, represented as a vector of unsigned 8-bit integers.
/// - `key1`: The first decryption key.
/// - `key2`: The second decryption key.
/// - `characters`: A string representing the set of characters used in the encryption.
/// - `password`: A password used in the decryption process.
///
/// # Returns
///
/// Returns the decrypted plain text on success. Returns a `SystemTrayError` on failure.
///
/// # Errors
///
/// Returns a `SystemTrayError` with code 1 if an invalid table position is encountered during decryption.
/// Returns a `SystemTrayError` with code 5 if there is an issue extracting characters from `key1` or `key2`.
/// Returns a `SystemTrayError` with code 6 if a character in the cipher text is not found in the character set.
///
/// # Examples
///
/// ```rust
/// let cipher_text = vec![/* vector of u8 representing cipher text */];
/// let key1 = "key1";
/// let key2 = "key2";
/// let characters = "abcdefghijklmnopqrstuvwxyz";
/// let password = "securepassword";
/// match decrypt(cipher_text, key1, key2, characters, password) {
///     Ok(plain_text) => {
///         println!("Plain Text: {}", plain_text);
///     },
///     Err(err) => {
///         println!("Error: {}", err);
///     },
/// }
/// ```
pub(crate) fn decrypt(cipher_text: Vec<u8>, key1: &str, key2: &str, characters: &str, password: &str) -> Result<String, SystemTrayError> {

    let val1 = addition_chiffres(key2);
    let val2 = addition_chiffres(key1);

    let seed = (val1 * val2) as u64;
    let table =  table2(characters, seed);
    let mut char_positions = HashMap::with_capacity(characters.len());
    characters.chars().enumerate().for_each(|(i, c)| {
        char_positions.insert(c, i);
    });

    let vz = kdfwagen(&[(val1+val2) as u8,(val1*val2) as u8, (val1%val2) as u8, (val1-val2) as u8, seed as u8], get_salt().as_bytes(), 10);
    let cipher_text = unshift_bits(cipher_text, &vz);
    let xor = xor_crypt(&kdfwagen(password.as_bytes(), get_salt().as_bytes(), 30), &cipher_text);
    let cipher_text = String::from_utf8_lossy(&xor).into_owned();

    let mut plain_text = String::with_capacity(cipher_text.len());
    for (i, c) in cipher_text.chars().enumerate() {
        let table_2d = key1.chars().nth(i % key1.len()).ok_or(SystemTrayError::new(5))? as usize % characters.len();
        let row = key2.chars().nth(i % key2.len()).ok_or(SystemTrayError::new(5))? as usize % characters.len();

        if table_2d < table.len() && row < table[table_2d].len() {
            let col = table[table_2d][row].iter().position(|&x| x == c).ok_or(SystemTrayError::new(6))?;
            let original_col = (col + characters.len()) % characters.len();

            plain_text.push(characters.chars().nth(original_col).ok_or(SystemTrayError::new(6))?);
        } else {
            return Err(SystemTrayError::new(1));
        }
    }

    Ok(plain_text.replace('^', ""))
}
/// Performs an XOR encryption/decryption on the given data using the provided key.
///
/// # Parameters
///
/// - `key`: A slice of unsigned 8-bit integers representing the key for the XOR operation.
/// - `data`: A slice of unsigned 8-bit integers representing the data to be XORed.
///
/// # Returns
///
/// Returns the result of the XOR operation as a vector of unsigned 8-bit integers.
///
/// # Examples
///
/// ```rust
/// let key = vec![/* vector of u8 representing the key */];
/// let data = vec![/* vector of u8 representing the data */];
/// let result = xor_crypt(&key, &data);
/// println!("{:?}", result);
/// ```
fn xor_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key_len = key.len();
    data.par_iter().enumerate().map(|(i, &byte)| byte ^ key[i % key_len]).collect()
}

/// Determines the character set for a specific language code and returns it as a static string.
///
/// The function uses the `whoami` crate to get the user's language code and returns the
/// corresponding character set based on the language.
///
/// # Returns
///
/// A static string representing the character set for the detected language or a default
/// character set if the language is not recognized.
///
/// # Examples
///
/// ```
/// use your_crate_name::localization;
///
/// let character_set = localization();
///
/// println!("Character Set: {}", character_set);
/// ```
fn localization() -> &'static str {
    let user_lang = whoami::lang().collect::<String>();
    match user_lang.as_str() {
        "fr" => "15^,&X_.w4Uek[?zv>|LOi9;83tgVxCdsrGHj#Ky+<hPQSR@nMDB2Z{cfI0l6-F}7EW$%Ybq'Jo=~:\"](Aa/p!uTN)*`m  ",
        "ar" => " ب ت ث ج ح خ د ذ ر ز س ش ص ض ط ظ ع غ ف ق ك ل م ن ١٢٣٤٥٦٧٨٩٠ ي0123456789!@#$%^&*()_+-={}[]<>?/|.,:;\"'`~ ",
        "el" => "αΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρστυφχψω0123456789!@#$%^&*()_+-={}[]<>?/|.,:;\"'`~ ",
        _ => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-={}[]<>?/|.,:;\"'`~ ",
    }
}

/// Shifts the bits of each byte in the cipher text based on the corresponding
/// values in the key.
///
/// # Arguments
///
/// * `cipher_text` - A vector of unsigned 8-bit integers representing the input cipher text.
/// * `key` - A slice of unsigned 8-bit integers representing the key for bit shifting.
///
/// # Returns
///
/// A new vector of unsigned 8-bit integers representing the result of shifting the bits.
///
/// # Examples
///
/// ```
/// use your_crate_name::shift_bits;
///
/// let cipher_text = vec![0b1100_0011, 0b1010_1100, 0b0101_0101];
/// let key = &[1, 2, 3];
///
/// let result = shift_bits(cipher_text, key);
///
/// assert_eq!(result, vec![0b1000_0111, 0b0101_1001, 0b1010_0101]);
/// ```
pub fn shift_bits(cipher_text: Vec<u8>, key: &[u8]) -> Vec<u8> {
    cipher_text.par_iter().enumerate().map(|(i, &byte)| {
        let shift_amount = key[i % key.len()];
        let rotated_byte = byte.rotate_left(shift_amount as u32);
        rotated_byte
    }).collect::<Vec<u8>>() // Collect into a Vec<u8>
}

/// Unshifts the bits of each byte in the cipher text based on the corresponding
/// values in the key.
///
/// # Arguments
///
/// * `cipher_text` - A vector of unsigned 8-bit integers representing the input cipher text.
/// * `key` - A slice of unsigned 8-bit integers representing the key for bit unshifting.
///
/// # Returns
///
/// A new vector of unsigned 8-bit integers representing the result of unshifting the bits.
///
/// # Examples
///
/// ```
/// use your_crate_name::unshift_bits;
///
/// let cipher_text = vec![0b1000_0111, 0b0101_1001, 0b1010_0101];
/// let key = &[1, 2, 3];
///
/// let result = unshift_bits(cipher_text, key);
///
/// assert_eq!(result, vec![0b1100_0011, 0b1010_1100, 0b0101_0101]);
/// ```
pub fn unshift_bits(cipher_text: Vec<u8>, key: &[u8]) -> Vec<u8> {
    cipher_text.par_iter().enumerate().map(|(i, &byte)| {
        let shift_amount = key[i % key.len()];
        let rotated_byte = byte.rotate_right(shift_amount as u32);
        rotated_byte
    }).collect::<Vec<u8>>() // Collect into a Vec<u8>
}

fn main() {
    let plain_text = "Le message est a une faible entropie : il est compose de peu de caracteres distincts";

    let characters = localization();

    let result = generate_key();

    if plain_text.len() > result.len() {
        println!("Erreur : la longueur du message est supérieure à la longueur de la clé");
        return;
    }

    println!("Key: {}", result);
    let password = "LeMOTdePAsse34!";

    let globalkey = match generate_key2(password) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("Erreur : {}", err);
            return;
        },

    };


    println!("seed value {}", addition_chiffres(&result) * addition_chiffres(&globalkey));
    println!("characters length {}", characters.len());
    let transpo =  transpose(characters, password.len()).unwrap();

    println!("Ke2: {}", globalkey);

    let encrypted_text = match encrypt(plain_text, &result, &globalkey, &transpo, password) {
        Ok(text) => text,
        Err(err) => {
            println!("Error during encryption: {}", err);
            return;
        }
    };

    let cipher_text = String::from_utf8_lossy(&encrypted_text).clone();
    println!("Cipher text: {}", cipher_text);

    println!("Encrypted text: {:?}", encrypted_text);


    let decrypted_text = match decrypt(encrypted_text, &result, &globalkey, &transpo, password) {
        Ok(text) => text,
        Err(err) => {
            println!("Error during decryption: {}", err);
            return;
        }
    };

    println!("Decrypted text: {}", decrypted_text);

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_table() {
        let characters = "zjpKYWmZfCgPs9.t3JS@r&%XRO5oUh$7e6Nvx84E^Q0qTLHV*MdDic!n(#1wBlIkGayuF2bA:-+/)";

        let transpo = transpose(characters, 10);



        let actual_table = table2(&transpo.unwrap(), 1234567890);

        assert_eq!(actual_table[0][0][0], '/');

        let test2 = table2(characters, 123456789);
        assert_ne!(actual_table, test2);
    }
    #[test]
    fn test_xor_crypt() {
        let key = b"Key";
        let data = b"HelloWorld";
        let encrypted_data = xor_crypt(key, data);
        let decrypted_data = xor_crypt(key, &encrypted_data);
        assert_eq!(decrypted_data, data);
    }
    #[test]
    fn test_encrypt() {
        let plain_text = "HelloWorld";
        let key1 = "Key1";
        let key2 = "Key2";
        let pass = "LeMOTdePAsse34!";
        let characters = "zjpKYWmZfCgPs9.t3JS@r&%XRO5oUh$7e6Nvx84E^Q0qTLHV*MdDic!n(#1wBlIkGayuF2bA:-+/)";
        let encrypted_text = encrypt(plain_text, key1, key2, characters, pass).unwrap();
        assert_ne!(encrypted_text, plain_text.as_bytes());
    }

    #[test]
    fn test_decrypt() {
        let plain_text = "HelloWorld";
        let key1 = "Key1";
        let key2 = "Key2";
        let pass = "LeMOTdePAsse34!";
        let characters = "zjpKYWmZfCgPs9.t3JS@r&%XRO5oUh$7e6Nvx84E^Q0qTLHV*MdDic!n(#1wBlIkGayuF2bA:-+/)";
        let encrypted_text = encrypt(plain_text, key1, key2, characters, pass).unwrap();
        let decrypted_text = decrypt(encrypted_text, key1, key2, characters, pass).unwrap();
        assert_eq!(decrypted_text, plain_text);
    }
    #[test]
    fn test_insert_random_stars() {
        let word = "HelloWorld";
        let word_with_stars = insert_random_stars(word);
        assert!(word_with_stars.len() >= word.len());
        assert!(word_with_stars.contains("^"));
    }

    #[test]
    fn test_table2() {
        let characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-={}[]<>?/|.,:;\"'`~ ";
        let seed = 1234567890;

        let actual_table = table2(&characters, seed);

        // Vérifiez ici les propriétés spécifiques de votre table.
        // Par exemple, vous pouvez vérifier que la taille de la table est correcte.
        assert_eq!(actual_table.len(), characters.len());
    }

    #[test]
    fn test_transpose() {
        let word = "HelloWorld";
        let shift = 3;
        let expected = "rldHWolelo";
        let result = transpose(word, shift);
        assert_eq!(result, Some(expected.to_string()));
    }

    #[test]
    fn test_shift_unshift_bits() {
        let original_data = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let key = &[5, 6, 7, 8, 9];

        // Test shift_bits
        let shifted_data = shift_bits(original_data.clone(), key);

        // Ensure that the shifted data is not equal to the original data
        assert_ne!(shifted_data, original_data);

        // Test unshift_bits
        let unshifted_data = unshift_bits(shifted_data, key);

        // Ensure that the unshifted data is equal to the original data
        assert_eq!(unshifted_data, original_data);
    }
}
