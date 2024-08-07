mod protocol;

use num_bigint::BigUint;
use protocol::packet::*;
use protocol::encoder::*;
use protocol::protocol::Protocol;

fn main() {
    // 示例：创建一个 ConnectPacket 并编码
    let mut connect_packet = ConnectPacket::new();
    connect_packet.version = 1;
    connect_packet.client_key = String::from("client_key");
    connect_packet.device_id = String::from("device_id");
    connect_packet.device_flag = 1;
    connect_packet.client_timestamp = 123456789;
    connect_packet.uid = String::from("uid");
    connect_packet.token = String::from("token");

    // 创建 Protocol 实例
    let protocol = Protocol::new();

    // 编码 ConnectPacket
    let encoded = protocol.encode(&connect_packet.create_packet());

    // 打印编码后的数据
    println!("Encoded: {:?}", encoded);

    // 解码数据
    let decoded_packet = protocol.decode(&encoded);

    // 尝试将解码后的 Packet 转换回 ConnectPacket
    if let Some(decoded_connect_packet) = decoded_packet.packet_object.downcast_ref::<ConnectPacket>() {
        println!("Decoded ConnectPacket: {:?}", decoded_connect_packet);
    } else {
        println!("Failed to decode ConnectPacket");
    }
}
