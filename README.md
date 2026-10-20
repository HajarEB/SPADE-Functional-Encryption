
# Ace of SPADE — Functional Encryption

A Python research implementation of **Ace of SPADE (AoS)**, a lattice-based functional encryption scheme supporting selective decryption, ciphertext updates, and multi-user access control.

Based on the research paper *Ace of SPADE: Selective and PArtial DEcryption with Post-Quantum Security*.

## Overview

This project reproduces the core cryptographic operations of Ace of SPADE, a functional encryption construction designed to enable privacy-preserving analysis of encrypted data.

Unlike conventional encryption, functional encryption allows authorized users to obtain specific information about encrypted data without revealing the complete plaintext.

The implementation supports selective equality queries over encrypted vectors, enabling users to identify matching values while keeping other values encrypted.

## Key Features

- **Functional Encryption:** Implemented setup, encryption, functional key derivation, and selective decryption.
- **Lattice-Based Cryptography:** Implemented polynomial arithmetic and randomized sampling operations underlying the scheme.
- **Ciphertext Updates:** Implemented update-token generation and ciphertext relabeling without decrypting the underlying data.
- **Multi-User Support:** Extended the implementation to handle multiple data owners and users with individual registration requests and functional decryption keys.
- **Secure Communication:** Integrated RSA-OAEP, AES-GCM, and digital signatures for protected and authenticated exchanges.
- **Access Control:** Implemented registration-based authorization checks and user revocation.
- **Performance Evaluation:** Measured execution time and memory consumption across multiple cryptographic parameter configurations.

## System Workflow

1. The Key Center generates functional encryption keys.
2. Data owners register and encrypt their datasets.
3. Users register with a selection of data owners and target values.
4. The Key Center derives the corresponding functional decryption keys.
5. Authorized users perform selective equality checks on encrypted data.
6. Ciphertext labels can be updated using generated update tokens.
7. User access is revoked at the end of the simulated session.

## Technologies

- Python
- NumPy
- Cryptography
- PyCryptodome
- psutil
- Functional Encryption
- Lattice-Based Cryptography

## Performance Evaluation

The implementation includes four experimental configurations based on the original research paper.

| Parameter Set | Vector Size | Ring Degree | log2(q) |
|---------------|-------------|-------------|---------|
| Small | 100 | 4096 | 39 |
| Medium | 200 | 8192 | 42 |
| Large | 500 | 16384 | 43 |
| Extra Large | 1000 | 32768 | 47 |

Execution time and memory consumption are measured for:

- Setup
- Encryption
- Key derivation
- Decryption
- Token generation
- Ciphertext updates

## Installation

Install the required Python dependencies:

```bash
pip install numpy cryptography pycryptodome psutil
```

## Usage

Run the interactive application:

```bash
python sec_prot.py
```

The program prompts the user to select a parameter configuration, register users, specify authorized data owners and target values, and perform selective decryption.

Generated datasets and decryption results are saved in dedicated output directories.

## Project Structure

```text
.
├── sec_prot.py        # Cryptographic scheme and multi-user workflow
├── utils.py           # Authentication and encryption utilities
└── README.md          # Project documentation
```

## Reference

Hadjeres, M., Nuoskala, C., Abdinasibfar, H., and Michalas, A. (2025).

*Ace of SPADE: Selective and PArtial DEcryption with Post-Quantum Security.*

## Disclaimer

This project is an academic research implementation developed for the Security Protocols course at Tampere University.

It is intended for educational and experimental purposes and has not undergone an independent cryptographic security audit.
