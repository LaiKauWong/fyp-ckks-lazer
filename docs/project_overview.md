# Project Overview

## Project title
Extending LaZer with a Module-LWE Public-Key Encryption Module

## Goal
This final-year project aims to extend the LaZer cryptographic library with missing higher-level cryptographic functionality, with current focus on Module-LWE public-key encryption.

## Motivation
LaZer provides low-level algebraic and cryptographic building blocks, but some scheme-layer functionality is not directly available as reusable modules.
This project focuses on implementing such functionality on top of LaZer primitives.

## Main additions
### Module-LWE PKE
- context setup
- key generation
- encryption and decryption
- test support
- benchmark support
- Python demo scripts

## Main implementation directories
- `src/public_key_encryption/`
- `python/public_key_encryption/`
- `Makefile.pke`

## Scope note
The project goal is integration and implementation completeness within the LaZer ecosystem, rather than outperforming mature standalone cryptographic libraries.