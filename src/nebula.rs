use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use blake3::Hasher;


use sysinfo::{Networks, Pid, System};
use crate::kdfwagen::kdfwagen;
use crate::systemtrayerror::SystemTrayError;

const MAX_RESEED_INTERVAL: u128 = 60;
const MAX_POOL_SIZE: usize = 1024;
const RESEED_THRESHOLD: usize = 512;

pub struct Nebula {
    seed: u128,
    pool: Mutex<VecDeque<u8>>,
    last_reseed_time: u128,
    bytes_since_reseed: Mutex<usize>,
}

impl Nebula {
    pub fn new(seed: u128) -> Self {
        Nebula {
            seed,
            pool: Mutex::new(VecDeque::new()),
            last_reseed_time: 0,
            bytes_since_reseed: Mutex::new(0),
        }
    }
    pub fn add_entropy(&self) -> Result<(), SystemTrayError> {


        let mut pool = self.pool.lock().unwrap();
        if pool.len() >= MAX_POOL_SIZE {
            pool.pop_front();
        }

        let mut entropy_sources = data_computer().unwrap();
        self.shuffle_array(&mut entropy_sources);
        for source in &entropy_sources {
            let entropy_bytes = source.to_be_bytes();
            let mut hasher = Hasher::new();
            hasher.update(&entropy_bytes);
            let mut hash = [0; 64];
            hasher.finalize_xof().fill(&mut hash);
            pool.extend(hash.iter());
        }
        Ok(())
    }

    // Fonction pour mélanger un tableau
    fn shuffle_array<T>(&self, array: &mut [T]) {
        let mut rng = Nebula::new(secured_seed()); // use generate random number here
        rng.combine_entropy();
        let len = array.len();
        for i in (1..len).rev() {
            match rng.generate_bounded_number(0, i as u128) {
                Ok(random_number) => {
                    let j = random_number as usize;
                    array.swap(i, j);
                }
                Err(err) => {
                    eprintln!("SystemTrayError: {:?}", err);
                }
            }
        }
    }


    fn reseed(&mut self, new_seed: u128) {
        {
            let mut bytes_since_reseed = self.bytes_since_reseed.lock().unwrap();

            if *bytes_since_reseed < RESEED_THRESHOLD {
                return;
            }

            // Reset the byte counter early to allow reseeding based on adaptive conditions
            *bytes_since_reseed = 0;
        } // <- bytes_since_reseed goes out of scope here

        // Add entropy and combine it with the existing state
        let _ = self.add_entropy();
        let combined_entropy = self.combine_entropy();

        // Continue with the mutable borrow after bytes_since_reseed is dropped
        self.mix_entropy(combined_entropy);

        // Update the seed periodically based on time
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        if current_time - self.last_reseed_time > MAX_RESEED_INTERVAL {
            self.last_reseed_time = current_time;
            self.seed ^= new_seed;
        }
    }

    fn combine_entropy(&self) -> u128 {
        let mut combined_entropy = self.seed;

        let pool = self.pool.lock().unwrap();
        for byte in &*pool {
            combined_entropy = combined_entropy.wrapping_mul(33).wrapping_add(u128::from(*byte));
        }
        combined_entropy ^= self.last_reseed_time;
        combined_entropy
    }


    fn mix_entropy(&mut self, entropy: u128) {
        let entropy_bytes = entropy.to_be_bytes();

        let mut hasher = Hasher::new();
        hasher.update(self.pool.lock().unwrap().make_contiguous());
        hasher.update(&entropy_bytes);

        let mut hash = [0; 64];
        hasher.finalize_xof().fill(&mut hash);
        self.pool = Mutex::new(VecDeque::from(hash.to_vec()));
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
        self.reseed(last_byte as u128);

        random_bytes
    }

    fn generate_random_number(&mut self) -> u128 {
        let random_bytes = self.generate_random_bytes(8);

        let mut random_number: u128 = 0;

        for &byte in &random_bytes {
            random_number = (random_number << 8) | u128::from(byte);
        }

        random_number
    }


    pub fn generate_bounded_number(&mut self, min: u128, max: u128) -> Result<u128, SystemTrayError> {
        if min > max {
            return Err(SystemTrayError::new(9));
        }
        let random_number = self.generate_random_number();

        Ok(min + (random_number % (max - min + 1)))
    }
}

fn data_computer() -> Result<[u128; 10], SystemTrayError> {
    let sys = System::new_all();  // Create a new sysinfo System to get system information

    let total_memory = sys.total_memory();
    let used_memory = sys.used_memory();
    let total_swap = sys.total_swap();
    let nb_cpus = sys.cpus().len();
    let uptime = System::uptime() as u128;
    let boot_time =  System::uptime() as u128;

    let mut network_data = 0;
    let networks = Networks::new_with_refreshed_list();
    for (_, network) in &networks {
        network_data += network.received() + network.total_received() + network.transmitted() + network.total_transmitted() + network.packets_received() + network.total_packets_received() + network.packets_transmitted() + network.total_packets_transmitted() + network.errors_on_received() + network.total_errors_on_received() + network.errors_on_transmitted();
    }

    let pid_set: HashSet<&Pid> = sys.processes().keys().collect();

    let pid_disk_usage: u128 = pid_set.into_iter().map(|&pid| {
        if let Some(process) = sys.process(pid) {
            process.disk_usage().total_read_bytes as u128
        } else {
            0
        }
    }).sum();

    if pid_disk_usage == 0 {
        return Err(SystemTrayError::new(8));
    }

    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_nanos();

    let pid = std::process::id();

     Ok([time, pid.into(), total_memory as u128, used_memory as u128, total_swap as u128, nb_cpus.try_into().unwrap(), pid_disk_usage, uptime, boot_time, network_data as u128])


}

// Fonction secured_seed
fn secured_seed() -> u128 {
    let temps_actuel = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Le temps est revenu en arrière")
        .as_nanos();

    let donnee_entree = format!("{}", temps_actuel);

    let contexte = data_computer().unwrap();

    let context_bytes: Vec<u8> = contexte
        .iter()
        .flat_map(|&x| x.to_be_bytes().to_vec())
        .collect();

    let cle = kdfwagen(&context_bytes, donnee_entree.as_bytes(), 15);

    let (partie1, partie2) = cle.split_at(16);

    let somme1: u128 = partie1.iter().map(|&x| x as u128).sum();
    let somme2: u128 = partie2.iter().map(|&x| x as u128).sum();

    somme1 * somme2
}

pub fn shuffle<T>(items: &mut [T]) {
    let len = items.len();
    for i in (1..len).rev() {
        let j = (secured_seed() as usize) % (i + 1);
        items.swap(i, j);
    }
}

pub fn seeded_shuffle<T>(items: &mut [T], seed: usize) {
    let len = items.len();
    for i in (1..len).rev() {
        let j = (seed) % (i + 1);
        items.swap(i, j);
    }
}

////////// function test
fn monobit_test(sequence: &[u8]) -> bool {
    let total_bits = sequence.len() * 8;
    let mut one_bits: i32 = 0;

    for &byte in sequence {
        for i in 0..8 {
            one_bits = match one_bits.checked_add(((byte >> i) & 1) as i32) {
                Some(v) => v,
                None => return false, // or handle overflow in another way
            };
        }
    }

    let zero_bits = total_bits - one_bits as usize;
    let difference = (one_bits as isize - zero_bits as isize).abs();
    println!("{difference} sur {}", (total_bits as f64).sqrt());
    // The difference should be less than the square root of the total number of bits
    difference < (total_bits as f64).sqrt() as isize
}


#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use super::*;

    #[test]
    fn test_add_entropy() {
        let mut rng = Nebula::new(12345);
        let initial_state = rng.pool.lock().unwrap().clone();
        rng.add_entropy();
        println!("{:?} {:?}", initial_state, rng.pool.lock().unwrap());
        assert_ne!(*rng.pool.lock().unwrap(), initial_state, "L'ajout d'entropie n'a pas modifié l'état du générateur");
    }

    #[test]
    fn test_reseed() {
        let mut rng = Nebula::new(12345);
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
        let mut rng = Nebula::new(12345);
        let first = rng.generate_random_bytes(10);
        let second = rng.generate_random_bytes(10);
        assert_ne!(first, second, "Les deux appels à generate_random_bytes ont produit les mêmes résultats");
    }

    #[test]
    fn test_printer(){
        let mut rng = Nebula::new(12345);
        for _ in 0..10 {
            rng.reseed(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
            let random_bytes = rng.generate_random_number();
            println!("{:?}", random_bytes);
        }
    }
    #[test]
    fn test_generate_bounded_number() {
        let mut rng = Nebula::new(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        let mut distribution_counts = HashMap::new();

        for _ in 0..100 {
            let number = rng.generate_bounded_number(10, 20).unwrap();

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
    fn test_shuffle_string() {
        let mut s = "1234567890".chars().collect::<Vec<_>>();
        let original = s.clone().into_iter().collect::<String>();
        shuffle(&mut s);
        let shuffled = s.into_iter().collect::<String>();
        println!("shuffled: {}", shuffled);
        assert_ne!(shuffled, original, "The string was not shuffled");
    }

    #[test]
    fn test_seeded_shuffle() {
        let mut items = "1234567890".chars().collect::<Vec<_>>();
        let original = items.clone();
        seeded_shuffle(&mut items, 12345);
        assert_ne!(items, original, "Les éléments n'ont pas été mélangés");
        let shuffled = items.clone().into_iter().collect::<String>();
        println!("shuffled: {}", shuffled);
    }

    #[test]
    fn test_generate_bounded_number_distribution() {
        let mut rng = Nebula::new(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos());
        let mut distribution_counts = HashMap::new();

        for _ in 0..10000 {
            let number = rng.generate_bounded_number(10, 20).unwrap();

            // Update the distribution counter
            let count = distribution_counts.entry(number).or_insert(0);
            *count += 1;

            assert!(number >= 10 && number <= 20, "Generated number is outside the specified range");
        }

        // Check if the distribution is uniform
        for count in distribution_counts.values() {
            println!("count: {}", count);
            assert!(*count >= 830 && *count <= 1000, "Distribution is not uniform");
        }
    }

    #[test]
    fn test_monobit() {
        let mut rng = Nebula::new(12345);
        let sequence = rng.generate_random_bytes(1000000);
        assert!(monobit_test(&sequence), "La séquence générée n'a pas passé le test de monobit");
    }

    #[test]
    fn test_secureseed() {
        let a = secured_seed();
        println!("{a}");
        let mut rng = Nebula::new(a);

        for _ in 0..10 {
            let random_bytes = rng.generate_random_number();
            println!("{:?}", random_bytes);
        }

    }

    #[test]
    fn monte_carlo_test() {
        const SAMPLE_SIZE: usize = 10000;

        let mut nebula = Nebula::new(secured_seed());
        let mut ones_count:i64 = 0;
        let mut zeros_count:i64 = 0;

        for _ in 0..SAMPLE_SIZE {
            let random_bit = nebula.generate_bounded_number(0, 1).unwrap();

            match random_bit {
                0 => zeros_count += 1,
                1 => ones_count += 1,
                _ => panic!("Unexpected value from PRNG"),
            }
        }

        // Calculate the proportion of ones and zerosdo
        let ones_proportion = ones_count as f64 / SAMPLE_SIZE as f64;
        let zeros_proportion = zeros_count as f64 / SAMPLE_SIZE as f64;
        println!("{} || {}", ones_proportion, zeros_proportion);

        // Check if the proportions are roughly equal (within some tolerance)
        // Adjust the tolerance based on your requirements
        assert!((ones_proportion - zeros_proportion).abs() < 0.02);
    }
}