# Horizon-CryptoGraphie

![Logo](./proxy-image.png)

Horizon is a secure and flexible encryption tool designed for various use cases. It provides functionalities for generating cryptographic keys, encrypting and decrypting text using a customized algorithm, and includes a pseudo-random number generator (PRNG) for additional security features.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Components](#Components)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Tests](#tests)
- [Contribution](#contribution)
- [License](#license)

## Introduction

The system relies on a three-dimensional table of characters generated from a given character sequence and a random seed. Encryption keys are also securely generated from the device's MAC address.

## Features

- **Key Generation:** Horizon allows you to generate cryptographic keys based on your machine's MAC address and other system information.
- **Custom Encryption Algorithm:** The project implements a custom encryption algorithm that shuffles characters based on two keys and a password. This algorithm ensures a unique and secure encryption process.
- **Pseudo-Random Number Generator (PRNG):** Horizon includes a PRNG named Nebula, which gathers entropy from various system sources to generate random numbers.
- **Key Derivation Function (KDF):** The Key Derivation Function in Horizon utilizes HMAC-BLAKE3-512 for secure key derivation based on a password and salt.

## Components
1. Encryption Module

    - **encrypt3:** Encrypts plain text using the custom encryption algorithm.
    - **decrypt3:** Decrypts cipher text using the custom encryption algorithm.
    - **xor_crypt3:** Performs XOR-based encryption or decryption on a given byte slice.
    - **shift_bits and unshift_bits:** Shifts or unshifts bits in a byte slice based on a key.

2. PRNG Module (Nebula)

    - **Nebula:** A pseudo-random number generator that gathers entropy from system sources to generate random numbers.
    - **add_entropy:** Adds entropy to the PRNG.
    - **generate_bounded_number:** Generates a random number within a specified range.
    - **shuffle and seeded_shuffle:** Functions to shuffle slices randomly.

3. KDF Module

    - **hmac:** Computes HMAC-BLAKE3 for the Key Derivation Function (KDF).
    - **kdfwagen:** Performs the Key Derivation Function (KDF) based on HMAC-BLAKE3 for secure key derivation.

4. Error Handling (SystemTrayError)

    - **SystemTrayError:** Custom error type with specific error codes and messages.

## Requirements

- [Rust](https://www.rust-lang.org/) - The Rust programming language is required to compile and run the project.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Cameleon00722/horizon.git
   cd your-project
   ```

2. Compile the program:
   ```bash
   cargo build --release
   ```

## Usage

Run the program using the following command:

```bash
./target/release/program-name
```

Follow the displayed instructions to encrypt and decrypt messages.

## Tests

The project comes with unit tests to ensure the system's robustness. Run the tests with the following command:

```bash
cargo test
```

## Contribution

Contributions are welcome! Before submitting changes, please refer to [CONTRIBUTING.md](CONTRIBUTING.md) for detailed information on how to contribute to the project.

## License

This project is licensed under the [MIT License](LICENSE), which means you are free to use, modify, and distribute it as you see fit.
