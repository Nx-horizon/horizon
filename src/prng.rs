use std::time::{SystemTime, UNIX_EPOCH};

struct SimpleRNG {
    state: [u64; 4],
}

impl SimpleRNG {
    fn new() -> SimpleRNG {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Le temps actuel est antérieur à l'époque Unix")
            .as_nanos() as u64;

        SimpleRNG { state: [seed, seed, seed, seed] }
    }

    fn next(&mut self) -> u64 {
        let mut t = self.state[3];
        t ^= t << 11;
        t ^= t >> 8;
        self.state[3] = self.state[2];
        self.state[2] = self.state[1];
        self.state[1] = self.state[0];
        self.state[0] ^= t ^ (t >> 19);
        self.state[0]
    }

    fn gen_range(&mut self, min: u64, max: u64) -> u64 {
        assert!(min <= max, "min doit être inférieur ou égal à max");


        let range = max.wrapping_sub(min).wrapping_add(1);
        let mut random_value = self.next();
        random_value %= range;
        random_value.wrapping_add(min)
    }

    fn from_seed(seed: u64) -> SimpleRNG {
        SimpleRNG { state: [seed, seed, seed, seed] }
    }

    fn next_from_seed(&mut self, seed: u64) -> u64 {
        self.state = [seed, seed, seed, seed];
        self.next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_next() {
        let mut rng = SimpleRNG::new();
        let first = rng.next();
        let second = rng.next();
        assert_ne!(first, second, "Les deux nombres générés sont identiques");
    }

    #[test]
    fn test_gen_range() {
        let mut rng = SimpleRNG::new();
        let min = 10;
        let max = 20;
        for _ in 0..1000 {
            let random_value = rng.gen_range(min, max);
            println!("{}", random_value);
            assert!(random_value >= min && random_value <= max, "Le nombre généré est hors de la plage spécifiée");
        }
    }

    #[test]
    fn test_from_seed() {
        let seed = 12345;
        let rng = SimpleRNG::from_seed(seed);
        assert_eq!(rng.state[0], seed, "Le premier élément de l'état du RNG ne correspond pas à la graine donnée");
    }

    #[test]
    fn test_next_from_seed() {
        let mut rng = SimpleRNG::new();
        let seed = 12345;
        let first = rng.next_from_seed(seed);
        let second = rng.next_from_seed(seed);
        assert_eq!(first, second, "Les deux nombres générés ne sont pas identique");
    }
}