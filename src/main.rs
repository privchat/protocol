mod protocol;

use protocol::packet::*;
use protocol::protocol::Protocol;

fn main() {
    // 示例：创建一个 ConnectMessage 并编码
    let mut connect_message = ConnectMessage::new();
    connect_message.version = 1;
    connect_message.client_key = String::from("client_key");
    connect_message.device_id = String::from("device_id");
    connect_message.device_flag = 1;
    connect_message.client_timestamp = 123456789;
    connect_message.uid = String::from("uid");
    connect_message.token = String::from("token");

    // 创建 Protocol 实例
    let protocol = Protocol::new();

    // 编码 ConnectMessage
    let encoded = protocol.encode(&connect_message.create_packet());

    // 打印编码后的数据
    println!("Encoded: {:?}", encoded);

    // 解码数据
    let decoded_packet = protocol.decode(&encoded);

    // 尝试将解码后的 Packet 转换回 ConnectMessage
    if let Some(decoded_connect_message) = decoded_packet.message_object.downcast_ref::<ConnectMessage>() {
        println!("Decoded ConnectMessage: {:?}", decoded_connect_message);
    } else {
        println!("Failed to decode ConnectMessage");
    }
}
