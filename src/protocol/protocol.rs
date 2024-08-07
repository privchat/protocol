use md5::{Digest, Md5};
use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use std::any::Any;
use std::collections::HashMap;

use crate::protocol::decoder::Decoder;
use crate::protocol::encoder::Encoder;
use crate::protocol::packet::{
    ConnectAckPacket, ConnectPacket, DisconnectPacket, Packet, PacketType, PingPacket, PongPacket,
    RecvAckPacket, RecvPacket, SendAckPacket, SendPacket, Setting, SubAckPacket, SubPacket,
};
use crate::protocol::security::SecurityManager;

static mut SERVER_VERSION: u8 = 0; // 服务端返回的协议版本

pub struct Protocol {
    packet_encode_map: HashMap<PacketType, fn(&dyn Any) -> Vec<u8>>,
    packet_decode_map:
        HashMap<PacketType, fn(&Packet<Box<dyn Any>>, &mut Vec<u8>) -> Packet<Box<dyn Any>>>,
}

impl Protocol {
    pub fn new() -> Self {
        let mut packet_encode_map: HashMap<PacketType, fn(&dyn Any) -> Vec<u8>> = HashMap::new();
        packet_encode_map.insert(
            PacketType::Connect,
            Self::encode_connect as fn(&dyn Any) -> Vec<u8>,
        );
        packet_encode_map.insert(
            PacketType::Send,
            Self::encode_send as fn(&dyn Any) -> Vec<u8>,
        );
        packet_encode_map.insert(
            PacketType::RecvAck,
            Self::encode_recv_ack as fn(&dyn Any) -> Vec<u8>,
        );
        packet_encode_map.insert(PacketType::Sub, Self::encode_sub as fn(&dyn Any) -> Vec<u8>);

        let mut packet_decode_map: HashMap<
            PacketType,
            fn(&Packet<Box<dyn Any>>, &mut Vec<u8>) -> Packet<Box<dyn Any>>,
        > = HashMap::new();
        packet_decode_map.insert(
            PacketType::Connect,
            Self::decode_connect as fn(&Packet<Box<dyn Any>>, &mut Vec<u8>) -> Packet<Box<dyn Any>>,
        );
        packet_decode_map.insert(
            PacketType::ConnectAck,
            Self::decode_connect_act
                as fn(&Packet<Box<dyn Any>>, &mut Vec<u8>) -> Packet<Box<dyn Any>>,
        );
        packet_decode_map.insert(
            PacketType::Recv,
            Self::decode_recv_packet
                as fn(&Packet<Box<dyn Any>>, &mut Vec<u8>) -> Packet<Box<dyn Any>>,
        );
        packet_decode_map.insert(
            PacketType::SendAck,
            Self::decode_send_ack_packet
                as fn(&Packet<Box<dyn Any>>, &mut Vec<u8>) -> Packet<Box<dyn Any>>,
        );
        packet_decode_map.insert(
            PacketType::Disconnect,
            Self::decode_disconnect
                as fn(&Packet<Box<dyn Any>>, &mut Vec<u8>) -> Packet<Box<dyn Any>>,
        );
        packet_decode_map.insert(
            PacketType::SubAck,
            Self::decode_sub_ack as fn(&Packet<Box<dyn Any>>, &mut Vec<u8>) -> Packet<Box<dyn Any>>,
        );

        Self {
            packet_encode_map,
            packet_decode_map,
        }
    }

    pub fn encode(&self, f: &Packet<Box<dyn Any>>) -> Vec<u8> {
        let mut enc = Vec::new();
        let body;
        println!("编码包: {:?}", f);
        if f.packet_type != PacketType::Ping && f.packet_type != PacketType::Pong {
            let packet_encode_func = self.packet_encode_map.get(&f.packet_type).unwrap();
            body = packet_encode_func(f.packet_object.as_ref());
            let header = Self::encode_framer(f, body.len());
            enc.extend(header);
            enc.extend(body);
        } else {
            let header = Self::encode_framer(f, 0);
            enc.extend(header);
        }
        enc
    }

    pub fn decode(&self, data: &[u8]) -> Packet<Box<dyn Any>> {
        let mut decode = data.to_vec();
        let f = Self::decode_framer(&mut decode);
        println!("解码包: {:?}", f);
        if f.packet_type == PacketType::Ping {
            return Packet::new(Box::new(PingPacket::new()), PacketType::Ping);
        }
        if f.packet_type == PacketType::Pong {
            return Packet::new(Box::new(PongPacket::new()), PacketType::Pong);
        }
        let packet_decode_func = self
            .packet_decode_map
            .get(&f.packet_type)
            .unwrap_or_else(|| panic!("不支持的包类型: {:?}", f.packet_type));
        packet_decode_func(&f, &mut decode)
    }

    fn encode_connect(packet: &dyn Any) -> Vec<u8> {
        let mut enc = Encoder::new();
        let p = packet.downcast_ref::<ConnectPacket>().unwrap();
        enc.write_uint8(p.version);
        enc.write_uint8(p.device_flag); // deviceFlag 0x01表示web
        enc.write_string(&p.device_id);
        enc.write_string(&p.uid);
        enc.write_string(&p.token);
        enc.write_int64(&BigUint::from(p.client_timestamp as u64));
        enc.write_string(&p.client_key);
        enc.to_uint8_array()
    }

    fn encode_send(packet: &dyn Any) -> Vec<u8> {
        let mut enc = Encoder::new();
        let p = packet.downcast_ref::<SendPacket>().unwrap();
        let mut p_mut = p.clone(); // 克隆 SendPacket，使其可变

        // setting
        enc.write_uint8(p_mut.setting.to_uint8());

        // messageID
        enc.write_int32(p_mut.client_seq as i32);

        // clientMsgNo
        if p_mut.client_msg_no.is_empty() {
            p_mut.client_msg_no = get_uuid();
        }
        enc.write_string(&p_mut.client_msg_no);

        if p_mut.setting.stream_on() {
            enc.write_string(&p_mut.stream_no);
        }

        // channel
        enc.write_string(&p_mut.channel_id);
        enc.write_uint8(p_mut.channel_type);
        if unsafe { SERVER_VERSION } >= 3 {
            enc.write_int32(p_mut.expire.unwrap_or(0) as i32);
        }
        // msg key
        let payload = SecurityManager::shared()
            .lock()
            .unwrap()
            .encryption2(&p_mut.payload);
        let msg_key = SecurityManager::shared()
            .lock()
            .unwrap()
            .encryption(&p_mut.verify_string());
        let mut hasher = Md5::new();
        hasher.update(&msg_key);
        enc.write_string(&format!("{:x}", hasher.finalize()));

        // topic
        if p_mut.setting.topic {
            enc.write_string(p_mut.topic.as_deref().unwrap_or(""));
        }

        // payload
        if !payload.is_empty() {
            enc.write_bytes(payload.as_bytes());
        }

        enc.to_uint8_array()
    }

    fn encode_sub(packet: &dyn Any) -> Vec<u8> {
        let mut enc = Encoder::new();
        let p = packet.downcast_ref::<SubPacket>().unwrap();
        enc.write_uint8(p.setting);
        enc.write_string(&p.client_msg_no);
        enc.write_string(&p.channel_id);
        enc.write_uint8(p.channel_type);
        enc.write_uint8(p.action);
        enc.write_string(p.param.as_deref().unwrap_or(""));
        enc.to_uint8_array()
    }

    fn decode_sub_ack(f: &Packet<Box<dyn Any>>, decode: &mut Vec<u8>) -> Packet<Box<dyn Any>> {
        let mut p = SubAckPacket::new();
        let mut dec = Decoder::new(decode.clone());
        p.client_msg_no = dec.read_string();
        p.channel_id = dec.read_string();
        p.channel_type = dec.read_byte();
        p.action = dec.read_byte();
        p.reason_code = dec.read_byte();
        Packet::new(Box::new(p), PacketType::SubAck)
    }

    fn encode_recv_ack(packet: &dyn Any) -> Vec<u8> {
        let mut enc = Encoder::new();
        let p = packet.downcast_ref::<RecvAckPacket>().unwrap();
        let message_id_biguint = BigUint::parse_bytes(p.message_id.as_bytes(), 10).unwrap();
        enc.write_int64(&message_id_biguint);
        enc.write_int32(p.message_seq as i32);
        enc.to_uint8_array()
    }

    fn decode_connect_act(f: &Packet<Box<dyn Any>>, decode: &mut Vec<u8>) -> Packet<Box<dyn Any>> {
        let mut p = ConnectAckPacket::new();
        let mut dec = Decoder::new(decode.clone());

        if f.packet_type == PacketType::ConnectAck {
            p.server_version = dec.read_byte();
            unsafe {
                SERVER_VERSION = p.server_version;
            }
            println!("服务器协议版本: {}", p.server_version);
        }

        p.time_diff = dec.read_int64().into();
        p.reason_code = dec.read_byte();
        p.server_key = dec.read_string();
        p.salt = dec.read_string();
        if p.server_version >= 4 {
            p.node_id = dec.read_int64().into();
        }

        Packet::new(Box::new(p), PacketType::ConnectAck)
    }

    fn decode_connect(f: &Packet<Box<dyn Any>>, decode: &mut Vec<u8>) -> Packet<Box<dyn Any>> {
        let mut p = ConnectPacket::new();
        let mut dec = Decoder::new(decode.clone());
        p.version = dec.read_byte();
        p.device_flag = dec.read_byte();
        p.device_id = dec.read_string();
        p.uid = dec.read_string();
        p.token = dec.read_string();
        p.client_timestamp = dec.read_int64().to_u64().unwrap() as i64;
        p.client_key = dec.read_string();
        Packet::new(Box::new(p), PacketType::Connect)
    }

    fn decode_disconnect(f: &Packet<Box<dyn Any>>, decode: &mut Vec<u8>) -> Packet<Box<dyn Any>> {
        let mut p = DisconnectPacket::new();
        let mut dec = Decoder::new(decode.clone());
        p.reason_code = dec.read_byte();
        p.reason = dec.read_string();
        Packet::new(Box::new(p), PacketType::Disconnect)
    }

    fn decode_recv_packet(f: &Packet<Box<dyn Any>>, decode: &mut Vec<u8>) -> Packet<Box<dyn Any>> {
        let mut p = RecvPacket::new();
        let mut dec = Decoder::new(decode.clone());
        p.setting = Setting::from_uint8(dec.read_byte());
        p.msg_key = dec.read_string();
        p.from_uid = dec.read_string();
        p.channel_id = dec.read_string();
        p.channel_type = dec.read_byte();
        if unsafe { SERVER_VERSION } >= 3 {
            p.expire = Some(dec.read_int32());
        }
        p.client_msg_no = dec.read_string();
        if p.setting.stream_on() {
            p.stream_no = dec.read_string();
            p.stream_seq = dec.read_int32();
            p.stream_flag = dec.read_byte().into();
        }
        p.message_id = dec.read_int64().to_string();
        p.message_seq = dec.read_int32();
        p.timestamp = dec.read_int32();
        if p.setting.topic {
            p.topic = Some(dec.read_string());
        }
        p.payload = dec.read_remaining();
        Packet::new(Box::new(p), PacketType::Recv)
    }

    fn decode_send_ack_packet(
        f: &Packet<Box<dyn Any>>,
        decode: &mut Vec<u8>,
    ) -> Packet<Box<dyn Any>> {
        let mut p = SendAckPacket::new();
        let mut dec = Decoder::new(decode.clone()); // 传递 Vec 的所有权
        p.message_id = dec.read_int64().into();
        p.client_seq = dec.read_int32();
        p.message_seq = dec.read_int32();
        p.reason_code = dec.read_byte();
        Packet::new(Box::new(p), PacketType::SendAck)
    }

    // 编码头部
    fn encode_framer(f: &Packet<Box<dyn Any>>, remaining_length: usize) -> Vec<u8> {
        if f.packet_type == PacketType::Ping || f.packet_type == PacketType::Pong {
            return vec![(f.packet_type as u8) << 4];
        }
        let mut headers = Vec::new();
        let type_and_flags = (Protocol::encode_bool(f.dup) << 3)
            | (Protocol::encode_bool(f.sync_once) << 2)
            | (Protocol::encode_bool(f.reddot) << 1)
            | Protocol::encode_bool(f.no_persist);
        headers.push((f.packet_type as u8) << 4 | type_and_flags);
        let vlen = Protocol::encode_variable_length(remaining_length);
        headers.extend(vlen);
        headers
    }

    fn decode_framer(decode: &mut Vec<u8>) -> Packet<Box<dyn Any>> {
        let mut dec = Decoder::new(decode.clone());
        let b = dec.read_byte();
        let mut f = Packet {
            no_persist: (b & 0x01) > 0,
            reddot: ((b >> 1) & 0x01) > 0,
            sync_once: ((b >> 2) & 0x01) > 0,
            dup: ((b >> 3) & 0x01) > 0,
            remaining_length: 0,
            packet_type: PacketType::Reserved,
            packet_object: Box::new(()) as Box<dyn Any>,
        };
        f.packet_type = unsafe { std::mem::transmute(b >> 4) };
        if f.packet_type != PacketType::Ping && f.packet_type != PacketType::Pong {
            f.remaining_length = dec.read_variable_length() as usize;
        }
        f
    }

    fn encode_bool(b: bool) -> u8 {
        if b {
            1
        } else {
            0
        }
    }

    fn encode_variable_length(mut len: usize) -> Vec<u8> {
        let mut ret = Vec::new();
        while len > 0 {
            let mut digit = len % 0x80;
            len /= 0x80;
            if len > 0 {
                digit |= 0x80;
            }
            ret.push(digit as u8);
        }
        ret
    }
}

fn get_uuid() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..32)
        .map(|i| {
            if i == 12 {
                '4'
            } else if i == 16 {
                let r = rng.gen_range(0..16);
                char::from_digit((r & 0x3 | 0x8) as u32, 16).unwrap()
            } else {
                let r = rng.gen_range(0..16);
                char::from_digit(r as u32, 16).unwrap()
            }
        })
        .collect()
}

impl Packet<Box<dyn Any>> {
    pub fn as_any(&self) -> &dyn Any {
        self.packet_object.as_ref()
    }
}
