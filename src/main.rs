// Author: sdev

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn generate_rsa_keys() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA private key");
    let pub_key = RsaPublicKey::from(&priv_key);
    (priv_key, pub_key)
}

fn encrypt_file(file_path: &Path, pub_key: &RsaPublicKey) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    let mut key_bytes = [0u8; 32];
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, buffer.as_ref())
        .map_err(|e| format!("Symmetric encryption error: {:?}", e))?;

    let mut rng = rand::thread_rng();
    let padding = Oaep::new::<Sha256>();
    let encrypted_key = pub_key.encrypt(&mut rng, padding, &key_bytes)?;

    let mut out_file = File::create(file_path)?;
    out_file.write_all(&(encrypted_key.len() as u32).to_le_bytes())?;
    out_file.write_all(&encrypted_key)?;
    out_file.write_all(&nonce_bytes)?;
    out_file.write_all(&ciphertext)?;

    let mut new_path = file_path.to_path_buf();
    let new_filename = format!("{}.enc", file_path.file_name().unwrap().to_str().unwrap());
    new_path.set_file_name(new_filename);
    fs::rename(file_path, new_path)?;

    Ok(())
}

fn decrypt_file(file_path: &Path, priv_key: &RsaPrivateKey) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open(file_path)?;
    
    let mut key_len_bytes = [0u8; 4];
    file.read_exact(&mut key_len_bytes)?;
    let key_len = u32::from_le_bytes(key_len_bytes) as usize;

    let mut encrypted_key = vec![0u8; key_len];
    file.read_exact(&mut encrypted_key)?;

    let mut nonce_bytes = [0u8; 12];
    file.read_exact(&mut nonce_bytes)?;

    let mut ciphertext = Vec::new();
    file.read_to_end(&mut ciphertext)?;

    let padding = Oaep::new::<Sha256>();
    let key_bytes = priv_key.decrypt(padding, &encrypted_key)?;

    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| format!("Symmetric decryption error: {:?}", e))?;

    let mut original_path = file_path.to_path_buf();
    let filename_str = file_path.file_name().unwrap().to_str().unwrap();
    if filename_str.ends_with(".enc") {
        let restored_filename = &filename_str[..filename_str.len() - 4];
        original_path.set_file_name(restored_filename);
    }

    let mut out_file = File::create(&original_path)?;
    out_file.write_all(&plaintext)?;

    fs::remove_file(file_path)?;

    Ok(())
}

fn process_directory<F>(target_dir: &Path, action: F)
where
    F: Fn(&Path) -> Result<(), Box<dyn std::error::Error>>,
{
    for entry in WalkDir::new(target_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            let _ = action(path);
        }
    }
}

fn main() {
    let target_folder = PathBuf::from("./lab_test_folder");
    if !target_folder.exists() {
        fs::create_dir_all(&target_folder).unwrap();
        let sample_file = target_folder.join("sample.txt");
        let mut f = File::create(sample_file).unwrap();
        writeln!(f, "Author: sdev - Hybrid Crypto Lab Verification File").unwrap();
    }

    let (priv_key, pub_key) = generate_rsa_keys();

    process_directory(&target_folder, |path| {
        encrypt_file(path, &pub_key)
    });

    process_directory(&target_folder, |path| {
        if path.extension().and_then(|s| s.to_str()) == Some("enc") {
            decrypt_file(path, &priv_key)
        } else {
            Ok(())
        }
    });
}

