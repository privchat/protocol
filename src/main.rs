use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use md5::{Md5, Digest};
use protocol::security::SecurityManager;
use std::str;
mod protocol;

use protocol::packet::*;
use protocol::protocol::Protocol;

use num_bigint::{BigUint, BigInt};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use rand::rngs::OsRng;
use rand::RngCore;

fn main() {

    ////////////////////////////////////////////////////////////////////////////////////
    ///////////////////// --------- 连接服务器消息
    ////////////////////////////////////////////////////////////////////////////////////
    let mut rng = OsRng;
    let mut random_bytes = [0u8; 32]; // Scalar 在 curve25519-dalek 中是 32 字节
    rng.fill_bytes(&mut random_bytes);

    // 使用 from_bits 方法创建 Scalar 实例
    let dh_private_key = Scalar::from_bits(random_bytes);

    // 模拟服务端公钥（实际上应该从 ConnectAckMessage 中获得）
    let server_pub_key = RISTRETTO_BASEPOINT_POINT * dh_private_key;
    let server_pub_key_bytes = server_pub_key.compress().to_bytes();
    let server_pub_key_base64 = BASE64_STANDARD.encode(&server_pub_key_bytes);
    
    println!("Generated server_pub_key_base64: {}", server_pub_key_base64);

    // 计算共享密钥
    let shared_secret = dh_private_key * server_pub_key;
    // 将共享密钥转换为 CompressedRistretto，然后转换为字节数组
    let shared_secret_bytes = shared_secret.compress().to_bytes();

    // 使用 MD5 计算哈希值
    let mut hasher = Md5::new();
    hasher.update(shared_secret_bytes);
    let result = hasher.finalize();

    // 使用前 16 个字节作为 aes_key
    let aes_key = &result[0..16]; // 直接使用前 16 字节，不转换为 Base64 字符串
    let aes_iv = "123456789012".to_string(); // 示例中的 salt 值，实际应该从服务器的 salt 字段获取

    // 赋值给 SecurityManager
    {
        let mut security_manager = SecurityManager::shared().lock().unwrap();
        security_manager.aes_key = base64::encode(aes_key);  // `aes_key` 被转换为 Base64 存储
        security_manager.aes_iv = if aes_iv.len() > 16 {
            aes_iv[0..16].to_string()
        } else {
            aes_iv.clone()
        };
    }

    // 继续其他操作，例如解码 ConnectAckMessage
    let mut connect_ack_message = ConnectAckMessage::new();
    connect_ack_message.server_version = 2;
    connect_ack_message.time_diff = BigInt::from(1000);
    connect_ack_message.reason_code = 0;
    connect_ack_message.server_key = server_pub_key_base64.to_string(); // 示例中直接使用
    connect_ack_message.salt = aes_iv.clone(); // 使用 clone 避免 move

    let protocol = Protocol::new();
    let encoded_ack = protocol.encode(&connect_ack_message.create_packet());
    let decoded_ack_packet = protocol.decode(&encoded_ack);
    if let Some(decoded_connect_ack_message) = decoded_ack_packet.message_object.downcast_ref::<ConnectAckMessage>() {
        println!("Decoded ConnectAckMessage: {:?}", decoded_connect_ack_message);
    } else {
        println!("Failed to decode ConnectAckMessage");
    }


    ////////////////////////////////////////////////////////////////////////////////////
    ///////////////////// --------- 测试加解密
    ////////////////////////////////////////////////////////////////////////////////////
    // 需要加密的消息
    let message = b"Hello, World!";

    // 加密
    let encrypted = SecurityManager::shared()
        .lock()
        .unwrap()
        .encryption(message)
        .expect("Encryption failed");

    println!("Encrypted message: {:?}", encrypted);

    // 解密
    let decrypted = SecurityManager::shared()
        .lock()
        .unwrap()
        .decryption(&encrypted)
        .expect("Decryption failed");

    println!("Decrypted message: {:?}", String::from_utf8(decrypted).expect("Failed to convert to string"));


    ////////////////////////////////////////////////////////////////////////////////////
    ///////////////////// --------- 发送消息
    ////////////////////////////////////////////////////////////////////////////////////
    
    // 准备一个 SendMessage 示例
    let mut send_message = SendMessage::new();
    send_message.setting = Setting::new();
    send_message.client_seq = 12345;
    send_message.client_msg_no = String::from("unique_msg_no");
    send_message.stream_no = String::from("stream_001");
    send_message.channel_id = String::from("channel_01");
    send_message.channel_type = 1;
    send_message.payload = vec![1, 2, 3, 4, 5]; // 示例负荷数据

    // 假设你会将 encoded_send_message 发送给服务端
    println!("Encoded SendMessage: {:?}", send_message);

    // 编码 SendMessage
    let encoded_send_message = protocol.encode(&send_message.create_packet());

    // 解码 SendMessage (模拟从服务器接收后的解码过程)
    let decoded_send_packet = protocol.decode(&encoded_send_message);
    if let Some(decoded_send_message) = decoded_send_packet.message_object.downcast_ref::<SendMessage>() {
        println!("Decoded SendMessage: {:?}", decoded_send_message);
    } else {
        println!("Failed to decode SendMessage");
    }

}
