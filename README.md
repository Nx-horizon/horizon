# Projet de Cryptographie

![Logo](./proxy-image.png)

Ce projet implémente un système de cryptographie basé sur la permutation de caractères dans une table tridimensionnelle, utilisant des clés générées de manière sécurisée. Le cryptage est réalisé à l'aide d'une combinaison de techniques, y compris des opérations de permutation et de chiffrement XOR.

## Table des matières

- [Introduction](#introduction)
- [Fonctionnalités](#fonctionnalités)
- [Exigences](#exigences)
- [Installation](#installation)
- [Utilisation](#utilisation)
- [Tests](#tests)
- [Contribution](#contribution)
- [Licence](#licence)

## Introduction

Le système repose sur une table tridimensionnelle de caractères, générée à partir d'une séquence de caractères donnée et d'une graine aléatoire. Les clés de chiffrement sont également générées de manière sécurisée à partir de la MAC adresse de l'appareil.

## Fonctionnalités

- **Cryptage et Décryptage :** Le programme offre des fonctions pour crypter et décrypter des messages à l'aide de clés générées dynamiquement.
- **Tables de Caractères :** Les tables de caractères sont générées de manière à introduire une entropie élevée dans le processus de cryptage.
- **Sécurité des Clés :** Les clés de chiffrement sont générées en utilisant des techniques cryptographiques robustes.

## Exigences

- [Rust](https://www.rust-lang.org/) - Le langage de programmation Rust est nécessaire pour compiler et exécuter le projet.

## Installation

1. Clonez le dépôt :
   ```bash
   git clone https://github.com/Cameleon00722/horizon.git
   cd votre-projet
   ```

2. Compilez le programme :
   ```bash
   cargo build --release
   ```

## Utilisation

Exécutez le programme en utilisant la commande suivante :

```bash
./target/release/nom-du-programme
```

Suivez les instructions affichées pour crypter et décrypter des messages.

## Tests

Le projet est livré avec des tests unitaires pour assurer la robustesse du système. Exécutez les tests avec la commande suivante :

```bash
cargo test
```

## Contribution

Les contributions sont les bienvenues ! Avant de soumettre des modifications, veuillez consulter [CONTRIBUTING.md](CONTRIBUTING.md) pour obtenir des informations détaillées sur la manière de contribuer au projet.

## Licence

Ce projet est sous licence [MIT](LICENSE), ce qui signifie que vous êtes libre de l'utiliser, de le modifier et de le distribuer comme bon vous semble.
