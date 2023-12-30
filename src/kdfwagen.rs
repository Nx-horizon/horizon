use sha3::{Sha3_512, Digest};

fn hmac(key: &[u8], message: &[u8]) -> Vec<u8> {
    const BLOCK_SIZE: usize = 128; // Taille du bloc pour SHA-512


    // Ajuster la clé si elle est trop longue
    let mut adjusted_key = if key.len() > BLOCK_SIZE {
        let mut hasher = Sha3_512::new();
        hasher.update(key);
        hasher.finalize().to_vec()
    } else {
        key.to_vec()
    };

    // Remplir la clé si elle est trop courte
    if adjusted_key.len() < BLOCK_SIZE {
        adjusted_key.resize(BLOCK_SIZE, 0);
    }

    // Calculer les valeurs internes pour le masquage
    let ipad: Vec<u8> = adjusted_key.iter().map(|&b| b ^ 0x36).collect();
    let opad: Vec<u8> = adjusted_key.iter().map(|&b| b ^ 0x5C).collect();

    // Concaténer le masque interne avec le message
    let inner_input: Vec<u8> = ipad.into_iter().chain(message.iter().cloned()).collect();

    // Appliquer le hachage interne (SHA-512)
    let inner_hash = Sha3_512::digest(&inner_input);

    // Concaténer le masque externe avec le haché interne
    let outer_input: Vec<u8> = opad.into_iter().chain(inner_hash.iter().cloned()).collect();

    // Appliquer le hachage externe (SHA-256) pour obtenir la sortie finale
    Sha3_512::digest(&outer_input).to_vec()
}

// Fonction PBKDF2
fn kdfwagen(password: &[u8], salt: &[u8], iterations: usize, key_length: usize) -> Vec<u8> {
    const PRF_OUTPUT_SIZE: usize = 64; // Taille de sortie de la fonction de hachage utilisée (SHA-512)

    let mut result = Vec::new();
    let mut block_count = (key_length + PRF_OUTPUT_SIZE - 1) / PRF_OUTPUT_SIZE;

    if block_count > 255 {
        block_count = 255; // Limiter le nombre de blocs pour éviter le débordement
    }

    for block_index in 1..=block_count {
        let mut block = salt.to_vec();
        block.extend_from_slice(&block_index.to_be_bytes());

        let mut u = hmac(password, &block);

        let mut xor_result = u.clone();
        for _ in 2..=iterations {
            u = hmac(password, &u);
            xor_result.iter_mut().zip(u.iter()).for_each(|(a, b)| *a ^= b);
        }

        result.extend_from_slice(&xor_result[..std::cmp::min(PRF_OUTPUT_SIZE, key_length)]);
    }

    result.resize(key_length, 0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_hmac() {
        let key = b"key";
        let message = b"The quick brown fox jumps over the lazy dog";
        let expected = "2a18de870613ad3cb1d3ed660320c8508c1107915ab7d9eadc06723237e97de491e8ba87b3a2e2f4c61775e24e11f77bdd9e7406d5dca68e9c692c67fc3307b1";
        let result = hmac(key, message);
        assert_eq!(hex::encode(result), expected);
    }

    #[test]
    fn test_kdfwagen() {
        let password = b"password";
        let salt = b"salt";
        let iterations = 2;
        let key_length = 32;
        let expected = "4714bcc31299ffafd9bef3315f28596a77fc51e5dca321e485dbf67e203f7c5c";
        let result = kdfwagen(password, salt, iterations, key_length);
        assert_eq!(hex::encode(result), expected);
    }
}