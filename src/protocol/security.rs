extern crate aes_gcm;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::aes::Aes128;
use aes_gcm::Aes128Gcm; // Or `Aes256Gcm`
use aes_gcm::aead::generic_array::GenericArray;
use std::sync::Mutex;
use std::str;
use base64::{engine::general_purpose, Engine as _};

pub struct SecurityManager {
    aes_key: String,       // 消息加解密的 aes key
    aes_iv: String,        // 消息 aes iv
    registration_id: u32,  // 注册ID
    device_id: u32,
}

impl SecurityManager {
    pub fn shared() -> &'static Mutex<SecurityManager> {
        static mut INSTANCE: Option<Mutex<SecurityManager>> = None;
        unsafe {
            INSTANCE.get_or_insert_with(|| {
                Mutex::new(SecurityManager {
                    aes_key: String::new(),
                    aes_iv: String::new(),
                    registration_id: 0,
                    device_id: 2,
                })
            })
        }
    }

    pub async fn signal_decrypt(&self, recipient_id: &str, message_data: &[u8]) -> Vec<u8> {
        // Placeholder for the actual decryption logic
        message_data.to_vec()
    }

    pub async fn signal_encrypt(&self, recipient_id: &str, content_data: &[u8]) -> Vec<u8> {
        // Placeholder for the actual encryption logic
        content_data.to_vec()
    }

    pub fn string_to_uint(&self, s: &str) -> Vec<u8> {
        s.chars().map(|c| c as u8).collect()
    }

    pub fn encryption(&self, message: &str) -> String {
        let key = GenericArray::from_slice(self.aes_key.as_bytes());
        let iv = GenericArray::from_slice(self.aes_iv.as_bytes());
        let cipher = Aes128Gcm::new(key);

        let ciphertext = cipher.encrypt(iv, message.as_ref())
            .expect("encryption failure!");

        general_purpose::STANDARD.encode(&ciphertext)
    }

    pub fn decryption(&self, message: &[u8]) -> Vec<u8> {
        let key = GenericArray::from_slice(self.aes_key.as_bytes());
        let iv = GenericArray::from_slice(self.aes_iv.as_bytes());
        let cipher = Aes128Gcm::new(key);

        let decoded_message = general_purpose::STANDARD.decode(message).unwrap();
        let plaintext = cipher.decrypt(iv, decoded_message.as_ref())
            .expect("decryption failure!");

        plaintext
    }

    pub fn encryption2(&self, message: &[u8]) -> String {
        let encoded_string = String::from_utf8_lossy(message);
        let decoded_string = str::replace(&encoded_string, "\0", "");
        self.encryption(&decoded_string)
    }

    pub fn uint_to_string(&self, array: &[u8]) -> String {
        String::from_utf8_lossy(array).to_string()
    }
}

pub fn array_buffer_to_string(b: &[u8]) -> String {
    uint8_array_to_string(b)
}

pub fn uint8_array_to_string(arr: &[u8]) -> String {
    arr.iter().map(|&c| c as char).collect()
}
