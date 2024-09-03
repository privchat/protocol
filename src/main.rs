
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use md5::{Md5, Digest};
use protocol::security::SecurityManager;
mod protocol;

use protocol::packet::*;
use protocol::protocol::Protocol;

use num_bigint::BigInt;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rand::rngs::OsRng;
use rand::RngCore;

use msgtrans::packet::{Packet, PacketHeader};
use msgtrans::compression::CompressionMethod;

fn main() {
    println!("\n\n\n示例代码\n\n\n");

    println!("\n\n\n【连接服务器消息】\n\n\n");
    ////////////////////////////////////////////////////////////////////////////////////
    ///////////////////// --------- 连接服务器消息
    ////////////////////////////////////////////////////////////////////////////////////
    // 初始化随机数生成器并生成随机字节
    let mut rng = OsRng;
    let mut random_bytes = [0u8; 64]; // Scalar 在 curve25519-dalek 中仍然是 64 字节
    rng.fill_bytes(&mut random_bytes);

    // 使用 from_bytes_mod_order_wide 方法创建 Scalar 实例
    let dh_private_key = Scalar::from_bytes_mod_order_wide(&random_bytes);

    // 模拟服务端公钥（实际上应该从 ConnectAckMessage 中获得）
    let server_pub_key = RISTRETTO_BASEPOINT_POINT * dh_private_key;
    let server_pub_key_bytes = server_pub_key.compress().as_bytes().to_vec();
    let server_pub_key_base64 = BASE64_STANDARD.encode(&server_pub_key_bytes);

    println!("Generated server_pub_key_base64: {}", server_pub_key_base64);

    // 计算共享密钥
    let shared_secret = dh_private_key * server_pub_key;
    // 将共享密钥转换为 CompressedRistretto，然后转换为字节数组
    let shared_secret_bytes = shared_secret.compress().as_bytes().to_vec();

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

    println!("\n\n\n【连接确认消息】\n\n\n");
    ////////////////////////////////////////////////////////////////////////////////////
    ///////////////////// --------- 连接确认消息
    ////////////////////////////////////////////////////////////////////////////////////

    // 继续其他操作，例如解码 ConnectAckMessage
    // 初始化 ConnectAckMessage
    let mut connect_ack_message = ConnectAckMessage::new();
    connect_ack_message.protocol_version = 2;
    connect_ack_message.time_diff = BigInt::from(1000);
    connect_ack_message.reason_code = 0;
    connect_ack_message.server_key = "example_server_key".to_string(); // 示例中直接使用字符串
    connect_ack_message.salt = "example_salt".to_string(); // 示例中直接使用字符串

    // 创建 Protocol 对象
    let protocol = Protocol::new();
    let encoded_ack = protocol.encode::<ConnectAckMessage>(&connect_ack_message);

    // 创建 PacketHeader 对象
    let packet_header = PacketHeader {
        message_id: 1,
        message_length: encoded_ack.len() as u32,
        compression_type: CompressionMethod::None,
        extend_length: 0,
    };

    // 创建 Packet 对象
    let packet = Packet::new(packet_header, vec![], encoded_ack);

    // 序列化 Packet 对象
    let serialized = packet.to_bytes();
    println!("Serialized Packet: {:?}", serialized);

    // 反序列化 Packet 对象
    let deserialized_packet = Packet::from_bytes(&serialized);

    // 解码 ConnectAckMessage
    if let Some(decoded_connect_ack_message) = protocol.decode::<ConnectAckMessage>(&deserialized_packet.payload) {
        println!("Decoded ConnectAckMessage: {:?}", decoded_connect_ack_message);
    } else {
        println!("Failed to decode ConnectAckMessage");
    }


    println!("\n\n\n【测试加解密】\n\n\n");
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


    println!("\n\n\n【发送消息】\n\n\n");
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
    let encoded_send_message = protocol.encode::<SendMessage>(&send_message);

    // 解码 SendMessage (模拟从服务器接收后的解码过程)
    if let Some(decoded_send_message) = protocol.decode::<SendMessage>(&encoded_send_message) {
        println!("Decoded SendMessage: {:?}", decoded_send_message);
    } else {
        println!("Failed to decode SendMessage");
    }

    println!("\n\n\n【发送确认消息】\n\n\n");
    ////////////////////////////////////////////////////////////////////////////////////
    ///////////////////// --------- 发送确认消息
    ////////////////////////////////////////////////////////////////////////////////////

    // 准备一个 SendAckMessage 示例
    let mut send_ack_message = SendAckMessage::new();
    send_ack_message.client_seq = 54321;
    send_ack_message.message_id = BigInt::from(20000000001u64);
    send_ack_message.message_seq = 100;
    send_ack_message.reason_code = 0; // 表示成功

    // 编码 SendAckMessage
    let encoded_send_ack_message = protocol.encode::<SendAckMessage>(&send_ack_message);

    // 解码 SendAckMessage (模拟从服务器接收后的解码过程)
    if let Some(decoded_send_ack_message) = protocol.decode::<SendAckMessage>(&encoded_send_ack_message) {
        println!("Decoded SendAckMessage: {:?}", decoded_send_ack_message);
    } else {
        println!("Failed to decode SendAckMessage");
    }

    println!("\n\n\n【断开连接消息】\n\n\n");
    ////////////////////////////////////////////////////////////////////////////////////
    ///////////////////// --------- 断开连接消息
    ////////////////////////////////////////////////////////////////////////////////////

    // 准备一个 DisconnectMessage 示例
    let mut disconnect_message = DisconnectMessage::new();
    disconnect_message.reason_code = 1;
    disconnect_message.reason = String::from("User requested disconnect");

    // 编码 DisconnectMessage
    let encoded_disconnect_message = protocol.encode::<DisconnectMessage>(&disconnect_message);

    // 解码 DisconnectMessage (模拟从服务器接收后的解码过程)
    if let Some(decoded_disconnect_message) = protocol.decode::<DisconnectMessage>(&encoded_disconnect_message) {
        println!("Decoded DisconnectMessage: {:?}", decoded_disconnect_message);
    } else {
        println!("Failed to decode DisconnectMessage");
    }

    println!("\n\n\n【接收消息】\n\n\n");
    ////////////////////////////////////////////////////////////////////////////////////
    ///////////////////// --------- 接收消息
    ////////////////////////////////////////////////////////////////////////////////////

    // 准备一个 RecvMessage 示例
    let mut recv_message = RecvMessage::new();
    recv_message.setting = Setting::new();
    recv_message.msg_key = String::from("msg_key_value");
    recv_message.from_uid = String::from("sender_uid");
    recv_message.channel_id = String::from("channel_02");
    recv_message.message_id = String::from("10000000001");
    recv_message.channel_type = 2;
    recv_message.payload = vec![6, 7, 8, 9, 10]; // 示例负荷数据

    // 编码 RecvMessage
    let encoded_recv_message = protocol.encode::<RecvMessage>(&recv_message);

    // 解码 RecvMessage (模拟从服务器接收后的解码过程)
    if let Some(decoded_recv_message) = protocol.decode::<RecvMessage>(&encoded_recv_message) {
        println!("Decoded RecvMessage: {:?}", decoded_recv_message);
    } else {
        println!("Failed to decode RecvMessage");
    }

    println!("\n\n\n【接收确认消息】\n\n\n");
    ////////////////////////////////////////////////////////////////////////////////////
    ///////////////////// --------- 接收确认消息
    ////////////////////////////////////////////////////////////////////////////////////

    // 准备一个 RecvAckMessage 示例
    let mut recv_ack_message = RecvAckMessage::new();
    recv_ack_message.message_id = String::from("20000000001");
    recv_ack_message.message_seq = 101;

    // 编码 RecvAckMessage
    let encoded_recv_ack_message = protocol.encode::<RecvAckMessage>(&recv_ack_message);

    // 解码 RecvAckMessage (模拟从服务器接收后的解码过程)
    if let Some(decoded_recv_ack_message) = protocol.decode::<RecvAckMessage>(&encoded_recv_ack_message) {
        println!("Decoded RecvAckMessage: {:?}", decoded_recv_ack_message);
    } else {
        println!("Failed to decode RecvAckMessage");
    }

    println!("\n\n\n【订阅消息】\n\n\n");
    ////////////////////////////////////////////////////////////////////////////////////
    ///////////////////// --------- 订阅消息
    ////////////////////////////////////////////////////////////////////////////////////

    // 准备一个 SubscribeMessage 示例
    let mut subscribe_message = SubscribeMessage::new();
    subscribe_message.setting = 0;
    subscribe_message.client_msg_no = String::from("subscribe_msg_no");
    subscribe_message.channel_id = String::from("subscribe_channel_id");
    subscribe_message.channel_type = 3;
    subscribe_message.action = 0; // 订阅动作

    // 编码 SubscribeMessage
    let encoded_subscribe_message = protocol.encode::<SubscribeMessage>(&subscribe_message);

    // 解码 SubscribeMessage (模拟从服务器接收后的解码过程)
    if let Some(decoded_subscribe_message) = protocol.decode::<SubscribeMessage>(&encoded_subscribe_message) {
        println!("Decoded SubscribeMessage: {:?}", decoded_subscribe_message);
    } else {
        println!("Failed to decode SubscribeMessage");
    }

    println!("\n\n\n【订阅确认消息】\n\n\n");
    ////////////////////////////////////////////////////////////////////////////////////
    ///////////////////// --------- 订阅确认消息
    ////////////////////////////////////////////////////////////////////////////////////

    // 准备一个 SubscribeAckMessage 示例
    let mut subscribe_ack_message = SubscribeAckMessage::new();
    subscribe_ack_message.client_msg_no = String::from("subscribe_ack_msg_no");
    subscribe_ack_message.channel_id = String::from("subscribe_ack_channel_id");
    subscribe_ack_message.channel_type = 3;
    subscribe_ack_message.action = 1; // 订阅确认

    // 编码 SubscribeAckMessage
    let encoded_subscribe_ack_message = protocol.encode::<SubscribeAckMessage>(&subscribe_ack_message);

    // 解码 SubscribeAckMessage (模拟从服务器接收后的解码过程)
    if let Some(decoded_subscribe_ack_message) = protocol.decode::<SubscribeAckMessage>(&encoded_subscribe_ack_message) {
        println!("Decoded SubscribeAckMessage: {:?}", decoded_subscribe_ack_message);
    } else {
        println!("Failed to decode SubscribeAckMessage");
    }

}
