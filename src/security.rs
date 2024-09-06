use aes_gcm::{Aes128Gcm, KeyInit}; // Or `Aes256Gcm`
use aes_gcm::aead::{Aead, generic_array::GenericArray}; // 引入 Aead trait

use std::str;
use std::sync::Mutex;

pub struct SecurityManager {
    pub aes_key: String,       // 消息加解密的 aes key
    pub aes_iv: String,        // 消息 aes iv
    pub registration_id: u32,  // 注册ID
    pub device_id: u32,
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

    pub fn encryption(&self, message: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        // 确保 aes_key 的长度为 16 字节
        let key_bytes = &self.aes_key.as_bytes()[..16];
        let key = GenericArray::from_slice(key_bytes);
        let cipher = Aes128Gcm::new(key);
    
        // 确保 aes_iv 长度为 12 字节
        let nonce = GenericArray::from_slice(&self.aes_iv.as_bytes()[..12]); // 取前 12 字节
    
        // 加密操作并返回加密后的二进制数据
        cipher.encrypt(nonce, message)
    }
    
    pub fn decryption(&self, message: &[u8]) -> Result<Vec<u8>, aes_gcm::Error> {
        // 确保 aes_key 的长度为 16 字节
        let key_bytes = &self.aes_key.as_bytes()[..16];
        let key = GenericArray::from_slice(key_bytes);
        let cipher = Aes128Gcm::new(key);
    
        // 确保 aes_iv 长度为 12 字节
        let iv = GenericArray::from_slice(&self.aes_iv.as_bytes()[..12]); // 使用前 12 字节作为 nonce
    
        // 解密
        cipher.decrypt(iv, message)
    }

    pub fn uint_to_string(&self, array: &[u8]) -> String {
        String::from_utf8_lossy(array).to_string()
    }
}
