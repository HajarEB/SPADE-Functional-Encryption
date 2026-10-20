# Ace of SPADE: Post-Quantum Functional Encryption

Research-based implementation of **Ace of SPADE (AoS)**, a lattice-based Homomorphic Functional Encryption (HFE) scheme enabling selective and partial decryption of encrypted data.

Developed as part of the *Security Protocols* course at Tampere University, this project implements and evaluates the cryptographic scheme presented in the research paper *Ace of SPADE: Selective and PArtial DEcryption with Post-Quantum Security*.

## Overview

Traditional encryption protects sensitive data but generally requires full decryption before it can be analyzed.

Functional Encryption (FE) addresses this limitation by allowing authorized users to learn specific information from encrypted data without revealing the complete underlying plaintext.

Ace of SPADE extends this concept by supporting:

- Selective and partial decryption
- Privacy-preserving equality checks
- Lattice-based cryptographic operations
- Ciphertext updates
- Multi-user access control

The project focuses on implementing these mechanisms and evaluating their computational performance.

## Features

### Functional Encryption
- Implementation of the core AoS cryptographic operations.
- Encryption and controlled decryption of sensitive data.
- Selective information disclosure through functional decryption keys.

### Post-Quantum Cryptography
- Implementation based on lattice-based cryptographic techniques.
- Exploration of cryptographic constructions designed for resistance to quantum attacks.

### Multi-User Support (Bonus)
- Extended the implementation to support multiple users.
- Implemented user-specific access to encrypted information.
- Enabled selective information disclosure in a multi-user setting.

### Performance Evaluation
- Benchmarked the main cryptographic operations.
- Evaluated execution time and memory consumption.
- Conducted experiments with different parameter configurations.
- Compared experimental observations with the original research paper.

## Cryptographic Operations

The implementation covers the following operations:

| Operation | Description |
|-----------|-------------|
| Setup | Initialize cryptographic parameters and keys |
| Encryption | Encrypt input data |
| Key Derivation | Generate functional decryption keys |
| Decryption | Recover authorized information |
| Token Generation | Generate ciphertext update tokens |
| Update | Update encrypted data |

## Technologies

- Functional Encryption
- Homomorphic Encryption
- Lattice-Based Cryptography
- Post-Quantum Cryptography
- Performance Benchmarking

## Evaluation

The implementation follows the experimental methodology described in the original paper.

Four parameter configurations are considered:

| Configuration | Input Vector Size |
|---------------|-------------------|
| Small | 100 |
| Medium | 200 |
| Large | 500 |
| Extra Large | 1000 |

The evaluation focuses on:

- Execution time of cryptographic operations
- Memory consumption
- Scalability with increasing input sizes
- Comparison with the reference implementation

## Research Reference

Hadjeres, M., Nuoskala, C., Abdinasibfar, H., & Michalas, A. (2025).

*Ace of SPADE: Selective and PArtial DEcryption with Post-Quantum Security.*

## Academic Context

Developed at **Tampere University** as an individual programming project for the course *Security Protocols (COMP.SEC.220)*.

The implementation is an academic research reproduction and has not undergone an independent security audit.
