# Rust Hybrid Encryption PoC Lab

**Author:** sdev  
**Language:** Rust  
**Category:** Cryptography Research / Proof of Concept (PoC)  
**License:** MIT  

---

## 📌 Overview

**Rust Hybrid Encryption PoC Lab** adalah proyek laboratorium kriptografi berbasis bahasa pemrograman **Rust**. Proyek ini mendemonstrasikan implementasi sistem *Hybrid Encryption* modern yang menggabungkan efisiensi tinggi dari skema enkripsi simetris dengan keamanan distribusi kunci menggunakan enkripsi asimetris.

Sistem ini dirancang untuk memproses berkas dalam direktori secara otomatis, mengamankan isi berkas menggunakan **ChaCha20-Poly1305 (AEAD)**, lalu membungkus kunci simetris tersebut menggunakan kunci **RSA-2048 (OAEP-SHA256)**.

---

## ⚙️ Technical Architecture

Implementasi ini memanfaatkan dua lapisan enkripsi (*Dual-Layer Cryptography*):

1. **Symmetric Layer (Data Encryption)**:
   - **Algorithm**: ChaCha20-Poly1305 Authenticated Encryption with Associated Data (AEAD).
   - **Key Size**: 256-bit (32 bytes) acak yang dibuat per berkas.
   - **Nonce**: 96-bit (12 bytes) acak cryptographically secure.

2. **Asymmetric Layer (Key Management)**:
   - **Algorithm**: RSA (Rivest–Shamir–Adleman).
   - **Key Size**: 2048-bit.
   - **Padding Scheme**: OAEP (Optimal Asymmetric Encryption Padding) dipadu fungsi digest **SHA-256**.

3. **Binary File Structure (`.enc`)**:
   Setiap berkas terenkripsi disusun dengan struktur biner spesifik:
   `[4 bytes Length Kunci RSA] + [Encrypted ChaCha Key] + [12 bytes Nonce] + [Encrypted Data Body]`

---

## 🚀 Prerequisites & Requirements

Sebelum menjalankan proyek ini, pastikan sistem kamu memenuhi dependensi berikut:

- **Rust Toolchain**: `rustc` dan `cargo` (minimal versi 1.70.0).
- **Environment**: Termux (Android), Linux, macOS, atau Windows Subsystem for Linux (WSL).
- **Git**: Terinstal untuk manajemen repositori.

---

## 📖 Usage Guide

### 1. Kloning Repositori
Jalankan perintah berikut untuk mengunduh kode sumber:
```bash
git clone [https://github.com/Sdeveandteam/rust-poc-lab.git](https://github.com/Sdeveandteam/rust-poc-lab.git)
cd rust-poc-lab

