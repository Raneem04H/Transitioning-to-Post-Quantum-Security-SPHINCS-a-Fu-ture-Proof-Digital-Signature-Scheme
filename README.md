# Transitioning to Post-Quantum Security: SPHINCS+ Implementation

This repository contains the official Python implementation and evaluation for the research paper:

**"Transitioning to Post-Quantum Security: SPHINCS+, a Future-Proof Digital Signature Scheme"**

---

## 📌 Project Overview

As quantum computing threatens classical public-key cryptography such as RSA and ECC, this project implements and evaluates SPHINCS+, a stateless, hash-based digital signature scheme selected by NIST for post-quantum standardization.

This implementation focuses on:

* Message integrity verification
* Quantum-resilient digital signatures
* Tamper detection
* Practical performance evaluation
* Real-world cryptographic workflow simulation

SPHINCS+ is designed to remain secure even in the presence of large-scale quantum computing attacks.

---

## 🚀 Key Features

**Quantum Resistance**
Uses secure hash-based cryptographic structures designed to resist quantum attacks such as Shor’s algorithm.

**Stateless Design**
Eliminates the need to track used keys, unlike stateful schemes such as XMSS, reducing operational risks.

**Tamper Detection**
Detects any modification to signed messages, ensuring strong message integrity protection.

**Modular Implementation**
Separates key generation, signing, and verification processes for easy integration and testing.

**File Export Support**
Automatically saves keys, signatures, and messages for analysis and validation.

---


## ⚙ System Workflow

The script performs the following operations:

1. Key Generation
   Generates a SPHINCS+ public and private key pair.

2. Message Signing
   Signs a message using the private key.

3. Signature Verification
   Verifies the signature using the public key.

4. Tamper Detection Test
   Attempts verification using a modified message (expected to fail).

5. File Export
   Saves cryptographic outputs to the `./out` directory.

---
## Example Output
=== SPHINCS+ Digital Signature System (pqcrypto) ===

Original Message Verification Result: ✔ Valid  
Modified Message Verification Result: ✘ Invalid  

Public Key (hex): ...  
Private Key (hex): ...  
Signature length: XXXX bytes 

---

## 📊 Evaluation Results

Based on experimental testing:

**Message Integrity**
The system successfully detected all tampered messages.

**Quantum Resistance**
SPHINCS+ demonstrated strong resistance against quantum-based attack models.

**Performance Stability**
The implementation maintained reliable performance during testing.

**Usability**
The system can be used and deployed even by users without deep cryptographic expertise.

---

## 🔐 Security Applications

This implementation can be used in:

* Digital Forensics
* Secure Communications
* Post-Quantum Cryptography Research
* Academic Research and Education
* Secure Identity and Authentication Systems


