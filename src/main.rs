mod systemtrayerror;

use std::collections::hash_map::DefaultHasher;
use rand::Rng;
use sha3::{Digest, Sha3_512};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use rand::prelude::*;
use mac_address::get_mac_address;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use rand::rngs::OsRng;
use rayon::prelude::*;

//v 0.3.91


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

pub fn generate_key() -> String {
    let mut hasher = Sha3_512::new();


    match get_mac_address() {
        Ok(Some(mac_address)) => {
            let mac_address_str = mac_address.to_string();
            hasher.update(kdf(&mac_address_str, addition_chiffres(&mac_address_str)*10));
        },
        Ok(None) => println!("No MAC address found."),
        Err(e) => println!("Error: {}", e),


    }

    format!("{:x}", hasher.finalize())
}

fn addition_chiffres(adresse_mac: &str) -> u32 {
    adresse_mac
        .chars()
        .filter_map(|c| c.to_digit(10))
        .sum()
}


fn kdf(word: &str, turn: u32) -> String {
    let mut result = word.to_string();
    let salt = word.chars().rev().collect::<String>();
    let mut hasher = Sha3_512::new();

    for i in 0..turn {
        if let Some(transposed) = transpose(&result, i as usize) {
            result = transposed;
        }

        // XOR operation
        let mut xor_result = xor_crypt(result.as_bytes(), salt.as_bytes());
        xor_result = rotate_right(xor_result, i);
        result = String::from_utf8_lossy(&xor_result).into_owned();

        hasher.update(result.as_bytes());
        hasher.update(salt.as_bytes());
        let hasher_clone = hasher.clone();
        result = format!("{:x}", hasher_clone.finalize());
    }

    result
}

fn rotate_right(bytes: Vec<u8>, count: u32) -> Vec<u8> {
    bytes.into_iter().map(|b| b.rotate_right(count)).collect()
}

fn generate_key2(seed: &str) -> Result<String, &'static str> {

    if seed.len() < 10 {
        return Err("Le seed doit avoir au moins 10 caractères");
    }


    let seed = kdf(seed, 300);
    let mut hasher = Sha3_512::new();
    hasher.update(seed);

    let hash_result = hasher.finalize();

    Ok(format!("{:x}", hash_result))
}
fn concat_4096(s: &str) -> Result<String, &'static str> {
    if s.len() % 8 != 0 {
        return Err("La longueur du str doit être divisible par 8");
    }

    let chunk_size = s.len() / 8;
    let mut result = String::new();

    for i in 0..8 {
        let start = i * chunk_size;
        let end = start + chunk_size;
        let chunk = &s[start..end];

        let mut hasher = Sha3_512::new();
        hasher.update(chunk);
        let hash = hasher.finalize();
        result.push_str(&format!("{:x}", hash));
    }

    Ok(result)
}

// Fonction pour empoisonner à des positions aléatoires dans le mot
fn insert_random_stars(word: &str) -> String {
    let mut rng = OsRng;
    let num_stars = rng.gen_range(word.len()/2..word.len()*2);
    let mut word_chars: Vec<char> = word.chars().collect();
    let mut stars: Vec<char> = vec!['^'; num_stars];
    let mut indices: Vec<usize> = (0..=word_chars.len()).collect();
    indices.shuffle(&mut rng);

    for &index in indices.iter().take(num_stars) {
        word_chars.insert(index, stars.pop().unwrap());
    }

    word_chars.into_iter().collect()
}

pub(crate) fn encrypt(plain_text: &str, key1: &str, key2: &str, characters: &str, password: &str) -> Result<Vec<u8>, &'static str> {
    let plain_text_with_stars = insert_random_stars(plain_text);
    let table = table2(characters, (addition_chiffres(key2) * addition_chiffres(key1)) as u64);
    let mut char_positions = HashMap::with_capacity(characters.len());
    characters.chars().enumerate().for_each(|(i, c)| {
        char_positions.insert(c, i);
    });

    let mut cipher_text = String::with_capacity(plain_text_with_stars.len());

    for (i, c) in plain_text_with_stars.chars().enumerate() {
        let table_2d = key1.chars().nth(i % key1.len()).ok_or("Key1 is too short")? as usize % characters.len();
        let row = key2.chars().nth(i % key2.len()).ok_or("Key2 is too short")? as usize % characters.len();

        let col = *char_positions.get(&c).ok_or("Character not found in character set")? % characters.len();

        if table_2d < table.len() && row < table[table_2d].len() && col < table[table_2d][row].len() {
            cipher_text.push(table[table_2d][row][col]);
        } else {
            return Err("Index out of bounds");
        }
    }
    let xor = xor_crypt(kdf(password, 300).as_bytes(), cipher_text.as_bytes());

    Ok(xor)
}
pub(crate) fn decrypt(cipher_text: Vec<u8>, key1: &str, key2: &str, characters: &str, password: &str) -> Result<String, &'static str> {
    let table =  table2(characters, (addition_chiffres(key2) * addition_chiffres(key1)) as u64);
    let mut char_positions = HashMap::with_capacity(characters.len());
    characters.chars().enumerate().for_each(|(i, c)| {
        char_positions.insert(c, i);
    });

    let xor = xor_crypt(kdf(password, 300).as_bytes(), &cipher_text);
    let cipher_text = String::from_utf8_lossy(&xor).into_owned();

    let mut plain_text = String::with_capacity(cipher_text.len());
    for (i, c) in cipher_text.chars().enumerate() {
        let table_2d = key1.chars().nth(i % key1.len()).ok_or("Key1 is too short")? as usize % characters.len();
        let row = key2.chars().nth(i % key2.len()).ok_or("Key2 is too short")? as usize % characters.len();

        if table_2d < table.len() && row < table[table_2d].len() {
            let col = table[table_2d][row].iter().position(|&x| x == c).ok_or("Character not found in table")?;
            let original_col = (col + characters.len()) % characters.len();

            plain_text.push(characters.chars().nth(original_col).ok_or("Error in character set")?);
        } else {
            return Err("Index out of bounds");
        }
    }

    Ok(plain_text.replace("^", ""))
}

fn xor_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key_len = key.len();
    data.par_iter().enumerate().map(|(i, &byte)| byte ^ key[i % key_len]).collect()
}

fn main() {
    let plain_text = "Le message est a une faible entropie : il est compose de peu de caracteres distincts";

    let characters = "15^,&X_.w4Uek[?zv>|LOi9;83tgVxCdsrGHj#Ky+<hPQSR@nMDB2Z{cfI0l6-F}7EW$%Ybq'Jo=~:\"](Aa/p!uTN)*`m ";


    let result = concat_4096(&generate_key()).unwrap();

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

    let globalkey = concat_4096(&globalkey).unwrap();

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
    fn test_kdf() {
        let word = "HelloWorld";
        let kdf_result = kdf(word, 500);
        assert_ne!(kdf_result, word);
        assert!(kdf_result.len() > word.len());
        assert_ne!(kdf(word, 499), kdf(word, 500));
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

}