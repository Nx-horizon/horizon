# Horizon-CryptoGraphie

![Logo](./proxy-image.png)

This project implements a cryptography system based on character permutation within a three-dimensional table, using securely generated keys. Encryption is performed using a combination of techniques, including permutation operations, shift bits and XOR encryption. it also have it's own prng generator.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Tests](#tests)
- [Contribution](#contribution)
- [License](#license)

## Introduction

The system relies on a three-dimensional table of characters generated from a given character sequence and a random seed. Encryption keys are also securely generated from the device's MAC address.

## Features

- **Encryption and Decryption:** The program provides functions for encrypting and decrypting messages using dynamically generated keys.
- **Character Tables:** Character tables are generated to introduce high entropy into the encryption process.
- **Key Security:** Encryption keys are generated using robust cryptographic techniques.
- **Prng generator:** Implement unique version of yarrow to generate pseudo random number.

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
