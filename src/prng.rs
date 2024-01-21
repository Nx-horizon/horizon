use std::collections::VecDeque;
use std::io::Read;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use sha3::{Sha3_512, Digest};

const MAX_POOL_SIZE: usize = 1024;
const RESEED_THRESHOLD: usize = 512;

/// Represents the Yarrow cryptographic pseudorandom number generator.
///
/// # Fields
///
/// - `seed`: A 64-bit unsigned integer representing the initial seed for the generator.
/// - `pool`: A deque of unsigned 8-bit integers serving as the entropy pool.
/// - `last_reseed_time`: A 64-bit unsigned integer representing the time of the last reseed operation.
///
/// # Examples
///
/// ```rust
/// let yarrow_instance = Yarrow {
///     seed: 42,
///     pool: VecDeque::new(),
///     last_reseed_time: 0,
/// };
/// ```
struct Yarrow {
    seed: u64,
    pool: Mutex<VecDeque<u8>>,
    last_reseed_time: u64,
    bytes_since_reseed: Mutex<usize>,
}

/// Implements methods for the Yarrow cryptographic pseudorandom number generator.
impl Yarrow {
    fn new(seed: u64) -> Self {
        Yarrow {
            seed,
            pool: Mutex::new(VecDeque::new()),
            last_reseed_time: 0,
            bytes_since_reseed: Mutex::new(0),
        }
    }

    fn add_entropy(&self) -> std::io::Result<()> {
        let temp_path = "/sys/class/thermal/thermal_zone0/temp";
        let temp_data = std::fs::read_to_string(temp_path)?;
        let temp = temp_data.trim().parse::<u64>().expect("Could not parse temperature");

        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_nanos() as u64;

        let pid = std::process::id();

        let mut file = std::fs::File::open("/dev/urandom")?;
        let mut buffer = [0; 8];
        file.read_exact(&mut buffer)?;
        let random = u64::from_ne_bytes(buffer);

        let mut pool = self.pool.lock().unwrap();
        if pool.len() >= MAX_POOL_SIZE {
            pool.pop_front();
        }
        let entropy_sources = [temp, time, pid.into(), random];
        for source in &entropy_sources {
            let entropy_bytes = source.to_be_bytes();
            let mut hasher = Sha3_512::new();
            hasher.update(entropy_bytes);
            let hash = hasher.finalize();
            pool.extend(hash.iter().copied());
        }
        Ok(())
}

    fn reseed(&mut self, new_seed: u64) {
        {
            let mut bytes_since_reseed = self.bytes_since_reseed.lock().unwrap();
            //println!("bytes_since_reseed: {}", *bytes_since_reseed); // Add this line
            if *bytes_since_reseed < RESEED_THRESHOLD {
                return;
            }
            *bytes_since_reseed = 0;
        }
    self.add_entropy();
    let combined_entropy = self.combine_entropy();
    self.mix_entropy(combined_entropy);
    let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    if current_time - self.last_reseed_time > 60 {
        self.last_reseed_time = current_time;
        self.seed ^= new_seed;
    }
}

    /// Combines the current state of the Yarrow generator's entropy pool, seed, and last reseed time.
    ///
    /// # Returns
    ///
    /// Returns a 64-bit unsigned integer representing the combined entropy.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let yarrow_instance = Yarrow::new(42);
    /// let combined_entropy = yarrow_instance.combine_entropy();
    /// println!("{}", combined_entropy);
    /// ```
    fn combine_entropy(&self) -> u64 {
        let mut combined_entropy = self.seed;

        let pool = self.pool.lock().unwrap();
        for byte in &*pool {
            combined_entropy = combined_entropy.wrapping_mul(33).wrapping_add(u64::from(*byte));
        }
        combined_entropy ^= self.last_reseed_time;
        combined_entropy
    }

    /// Mixes additional entropy into the Yarrow generator's entropy pool using the SHA3-512 hashing algorithm.
    ///
    /// # Parameters
    ///
    /// - `entropy`: A 64-bit unsigned integer representing the additional entropy to be mixed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut yarrow_instance = Yarrow::new(42);
    /// let additional_entropy = 123;
    /// yarrow_instance.mix_entropy(additional_entropy);
    /// ```
    fn mix_entropy(&mut self, entropy: u64) {
        let entropy_bytes = entropy.to_be_bytes();

        let mut hasher = Sha3_512::new();
        hasher.update(&self.pool.lock().unwrap().make_contiguous());
        hasher.update(entropy_bytes);

        let hash = hasher.finalize();
        self.pool = VecDeque::from(hash.as_slice().to_vec()).into();
    }

    /// Generates a sequence of random bytes using the Yarrow generator.
    ///
    /// # Parameters
    ///
    /// - `count`: The number of random bytes to generate.
    ///
    /// # Returns
    ///
    /// Returns a vector of unsigned 8-bit integers representing the generated random bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut yarrow_instance = Yarrow::new(42);
    /// let random_bytes = yarrow_instance.generate_random_bytes(16);
    /// println!("{:?}", random_bytes);
    /// ```
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

    /// Generates a random 64-bit unsigned integer using the Yarrow generator.
    ///
    /// # Returns
    ///
    /// Returns a 64-bit unsigned integer representing the generated random number.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut yarrow_instance = Yarrow::new(42);
    /// let random_number = yarrow_instance.generate_random_number();
    /// println!("{}", random_number);
    /// ```
    fn generate_random_number(&mut self) -> u64 {
        let random_bytes = self.generate_random_bytes(8);

        let mut random_number: u64 = 0;

        for &byte in &random_bytes {
            random_number = (random_number << 8) | u64::from(byte);
        }

        random_number
    }

    /// Generates a random 64-bit unsigned integer within a specified range using the Yarrow generator.
    ///
    /// # Parameters
    ///
    /// - `min`: The minimum value of the generated number (inclusive).
    /// - `max`: The maximum value of the generated number (inclusive).
    ///
    /// # Returns
    ///
    /// Returns a 64-bit unsigned integer within the specified range.
    ///
    /// # Examples
    ///
    /// ```rust
    /// let mut yarrow_instance = Yarrow::new(42);
    /// let random_number = yarrow_instance.generate_bounded_number(10, 20);
    /// println!("{}", random_number);
    /// ```
    fn generate_bounded_number(&mut self, min: u64, max: u64) -> u64 {
        let random_number = self.generate_random_number();

        min + (random_number % (max - min + 1))
    }
}

/// Shuffles the elements of a mutable slice using the Fisher-Yates algorithm with a time-based seed.
///
/// # Parameters
///
/// - `items`: A mutable slice of elements to be shuffled.
///
/// # Examples
///
/// ```rust
/// let mut elements = vec![1, 2, 3, 4, 5];
/// shuffle(&mut elements);
/// println!("{:?}", elements);
/// ```
fn shuffle<T>(items: &mut [T]) {
    let len = items.len();
    for i in (1..len).rev() {
        let j = (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as usize) % (i + 1);
        items.swap(i, j);
    }
}

fn seeded_shuffle<T>(items: &mut [T], seed: usize) {
    let len = items.len();
    for i in (1..len).rev() {
        let j = (seed) % (i + 1);
        items.swap(i, j);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use super::*;

    #[test]
    fn test_add_entropy() {
        let mut rng = Yarrow::new(12345);
        let initial_state = rng.pool.lock().unwrap().clone();
        rng.add_entropy();
        assert_ne!(*rng.pool.lock().unwrap(), initial_state, "L'ajout d'entropie n'a pas modifié l'état du générateur");
    }

    #[test]
    fn test_reseed() {
        let mut rng = Yarrow::new(12345);
        let initial_state = rng.pool.lock().unwrap().clone();
        // Generate enough random bytes to meet the reseed threshold
        for _ in 0..(RESEED_THRESHOLD / 8) {
            rng.generate_random_bytes(8);
        }
        rng.reseed(67890);
        assert_ne!(*rng.pool.lock().unwrap(), initial_state, "La méthode reseed n'a pas modifié l'état du générateur");
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
        let mut rng = Yarrow::new(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64);
        let mut distribution_counts = HashMap::new();

        for _ in 0..1000 {
            let number = rng.generate_bounded_number(10, 20);

            // Mettez à jour le compteur de distribution
            let count = distribution_counts.entry(number).or_insert(0);
            *count += 1;

            assert!(number >= 10 && number <= 20, "Le nombre généré est hors de la plage spécifiée");
        }

        // Afficher la répartition des valeurs
        println!("Répartition des valeurs générées :");
        for (value, count) in &distribution_counts {
            println!("Valeur {}: {} fois", value, count);
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

    #[test]
    fn test_shuffle_string() {
        let mut s = "Hello, World!".chars().collect::<Vec<_>>();
        let original = s.clone().into_iter().collect::<String>();
        shuffle(&mut s);
        let shuffled = s.into_iter().collect::<String>();
        println!("shuffled: {}", shuffled);
        assert_ne!(shuffled, original, "The string was not shuffled");
    }

    #[test]
    fn test_seeded_shuffle() {
        let mut items = "Hello, World!".chars().collect::<Vec<_>>();
        let original = items.clone();
        seeded_shuffle(&mut items, 12345);
        assert_ne!(items, original, "Les éléments n'ont pas été mélangés");
        let shuffled = items.into_iter().collect::<String>();
        println!("shuffled: {}", shuffled);
        //assert_eq!(items, original, "Tous les éléments d'origine ne sont pas présents après le mélange");
    }
}
