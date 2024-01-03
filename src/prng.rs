use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};
use sha3::{Sha3_512, Digest};

struct Yarrow {
    seed: u64,
    pool: VecDeque<u8>,
    // Ajouter une source d'entropie basée sur le temps
    last_reseed_time: u64,
}

impl Yarrow {
    fn new(seed: u64) -> Self {
        Yarrow {
            seed,
            pool: VecDeque::new(),
            last_reseed_time: 0,
        }
    }

    fn add_entropy(&mut self, entropy: u64) {
        let entropy_bytes = entropy.to_be_bytes();
        let mut hasher = Sha3_512::new();
        hasher.update(&entropy_bytes);
        let hash = hasher.finalize();
        self.pool.extend(hash.iter().copied());
    }

    fn reseed(&mut self, new_seed: u64) {
        let external_entropy = new_seed;

        self.add_entropy(external_entropy);

        let combined_entropy = self.combine_entropy();
        self.mix_entropy(combined_entropy);

        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        if current_time - self.last_reseed_time > 60 {
            self.last_reseed_time = current_time;
            self.seed ^= new_seed;
        }
    }

    fn combine_entropy(&self) -> u64 {
        let mut combined_entropy = self.seed;
        for byte in &self.pool {
            combined_entropy = combined_entropy.wrapping_mul(33).wrapping_add(u64::from(*byte));
        }
        // Ajouter l'entropie basée sur le temps
        combined_entropy ^= self.last_reseed_time;
        combined_entropy
    }

    fn mix_entropy(&mut self, entropy: u64) {
        let entropy_bytes = entropy.to_be_bytes();
        let mut hasher = Sha3_512::new();
        hasher.update(&self.pool.make_contiguous());
        hasher.update(&entropy_bytes);
        let hash = hasher.finalize();
        self.pool = VecDeque::from(hash.as_slice().to_vec());
    }

    fn generate_random_bytes(&mut self, count: usize) -> Vec<u8> {
        let mut random_bytes = Vec::with_capacity(count);

        for _ in 0..count {
            let entropy = self.combine_entropy();
            self.mix_entropy(entropy);

            let random_byte = (entropy & 0xFF) as u8;
            random_bytes.push(random_byte);
        }

        let last_byte = random_bytes.last().copied().unwrap_or(0);
        self.reseed(last_byte as u64);

        random_bytes
    }

    fn generate_random_number(&mut self) -> u64 {
        let random_bytes = self.generate_random_bytes(8);
        let mut random_number: u64 = 0;

        for &byte in &random_bytes {
            random_number = (random_number << 8) | u64::from(byte);
        }

        random_number
    }

    fn generate_bounded_number(&mut self, min: u64, max: u64) -> u64 {
        let random_number = self.generate_random_number();
        min + (random_number % (max - min + 1))
    }
}

fn shuffle<T>(items: &mut [T]) {
    let len = items.len();
    for i in (1..len).rev() {
        let j = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as usize) % (i + 1);
        items.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_entropy() {
        let mut rng = Yarrow::new(12345);
        let initial_state = rng.pool.clone();
        rng.add_entropy(67890);
        assert_ne!(rng.pool, initial_state, "L'ajout d'entropie n'a pas modifié l'état du générateur");
    }

    #[test]
    fn test_reseed() {
        let mut rng = Yarrow::new(12345);
        let initial_state = rng.pool.clone();
        rng.reseed(67890);
        assert_ne!(rng.pool, initial_state, "La méthode reseed n'a pas modifié l'état du générateur");
    }

    #[test]
    fn test_generate_random_bytes() {
        let mut rng = Yarrow::new(12345);
        let first = rng.generate_random_bytes(10);
        let second = rng.generate_random_bytes(10);
        assert_ne!(first, second, "Les deux appels à generate_random_bytes ont produit les mêmes résultats");
    }

    #[test]
    fn test_printer(){
        let mut rng = Yarrow::new(12345);
        for _ in 0..10 {
            rng.reseed(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs());
            let random_bytes = rng.generate_random_number();
            println!("{:?}", random_bytes);
        }
    }
    #[test]
    fn test_generate_bounded_number() {
        let mut rng = Yarrow::new(12345);
        for _ in 0..1000 {
            let number = rng.generate_bounded_number(10, 20);
            assert!(number >= 10 && number <= 20, "Le nombre généré est hors de la plage spécifiée");
        }
    }

    #[test]
    fn test_shuffle() {
        let mut items = vec![1, 2, 3, 4, 5];
        let original = items.clone();
        shuffle(&mut items);
        assert_ne!(items, original, "Les éléments n'ont pas été mélangés");
        items.sort();
        assert_eq!(items, original, "Tous les éléments d'origine ne sont pas présents après le mélange");
    }
}