use md5::{Digest, Md5};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use std::any::Any;
use std::collections::HashMap;

use crate::protocol::decoder::Decoder;
use crate::protocol::encoder::Encoder;
use crate::protocol::packet::{
    ConnectAckMessage, ConnectMessage, DisconnectMessage, Packet, MesssageType, PingMessage, PongMessage,
    RecvAckMessage, RecvMessage, SendAckMessage, SendMessage, Setting, SubscribeAckMessage, SubscribeMessage,
};
use crate::protocol::security::SecurityManager;

static mut SERVER_VERSION: u8 = 0; // 服务端返回的协议版本

pub struct Protocol {
    message_encode_map: HashMap<MesssageType, fn(&dyn Any) -> Vec<u8>>,
    packet_decode_map:
        HashMap<MesssageType, fn(&Packet<Box<dyn Any>>, &mut Decoder) -> Packet<Box<dyn Any>>>,
}

impl Protocol {
    pub fn new() -> Self {
        let mut message_encode_map: HashMap<MesssageType, fn(&dyn Any) -> Vec<u8>> = HashMap::new();
        message_encode_map.insert(MesssageType::Connect, Self::encode_connect_message);
        message_encode_map.insert(MesssageType::Send, Self::encode_send_message);
        message_encode_map.insert(MesssageType::RecvAck, Self::encode_recv_ack_message);
        message_encode_map.insert(MesssageType::Subscribe, Self::encode_subscribe_message);

        let mut packet_decode_map: HashMap<
            MesssageType,
            fn(&Packet<Box<dyn Any>>, &mut Decoder) -> Packet<Box<dyn Any>>,
        > = HashMap::new();
        packet_decode_map.insert(MesssageType::Connect, Self::decode_connect_message);
        packet_decode_map.insert(MesssageType::ConnectAck, Self::decode_connect_ack_message);
        packet_decode_map.insert(MesssageType::Recv, Self::decode_recv_message);
        packet_decode_map.insert(MesssageType::SendAck, Self::decode_send_ack_message);
        packet_decode_map.insert(MesssageType::Disconnect, Self::decode_disconnect_message);
        packet_decode_map.insert(MesssageType::SubscribeAck, Self::decode_subscribe_ack_message);

        Self {
            message_encode_map,
            packet_decode_map,
        }
    }

    pub fn encode(&self, packet: &Packet<Box<dyn Any>>) -> Vec<u8> {
        let mut data = Vec::new();
        if packet.message_type != MesssageType::Ping && packet.message_type != MesssageType::Pong {
            let packet_encode_func = self.message_encode_map.get(&packet.message_type).unwrap();
            let body = packet_encode_func(&*packet.message_object);
            let header = Self::encode_framer(packet, body.len());
            data.extend(header);
            data.extend(body);
        } else {
            let header = Self::encode_framer(packet, 0);
            data.extend(header);
        }
        data
    }

    pub fn decode(&self, data: &[u8]) -> Packet<Box<dyn Any>> {
        let mut decoder = Decoder::new(data.to_vec());
        let f = Self::decode_framer(&mut decoder);
        if f.message_type == MesssageType::Ping {
            return Packet::new(Box::new(PingMessage::new()), MesssageType::Ping);
        }
        if f.message_type == MesssageType::Pong {
            return Packet::new(Box::new(PongMessage::new()), MesssageType::Pong);
        }
        let packet_decode_func = self
            .packet_decode_map
            .get(&f.message_type)
            .unwrap_or_else(|| panic!("不支持的包类型: {:?}", f.message_type));
        packet_decode_func(&f, &mut decoder)
    }

    fn encode_connect_message(message: &dyn Any) -> Vec<u8> {
        let mut enc = Encoder::new();
        let p = message.downcast_ref::<ConnectMessage>().unwrap();
        enc.write_uint8(p.version);
        enc.write_uint8(p.device_flag);
        enc.write_string(&p.device_id);
        enc.write_string(&p.uid);
        enc.write_string(&p.token);
        enc.write_int64(&BigUint::from(p.client_timestamp as u64));
        enc.write_string(&p.client_key);
        enc.to_uint8_array()
    }

    fn encode_send_message(message: &dyn Any) -> Vec<u8> {
        let mut enc = Encoder::new();
        let mut p = message.downcast_ref::<SendMessage>().unwrap().clone(); // 克隆 SendMessage
    
        enc.write_uint8(p.setting.to_uint8());
        enc.write_int32(p.client_seq as i32);
        if p.client_msg_no.is_empty() {
            p.client_msg_no = get_uuid();
        }
        enc.write_string(&p.client_msg_no);
    
        if p.setting.stream_on() {
            enc.write_string(&p.stream_no);
        }
    
        enc.write_string(&p.channel_id);
        enc.write_uint8(p.channel_type);
        if unsafe { SERVER_VERSION } >= 3 {
            enc.write_int32(p.expire.unwrap_or(0) as i32);
        }
    
        let payload = SecurityManager::shared()
            .lock()
            .unwrap()
            .encryption2(&p.payload);
        let msg_key = SecurityManager::shared()
            .lock()
            .unwrap()
            .encryption(&p.verify_string());
        let mut hasher = Md5::new();
        hasher.update(&msg_key);
        enc.write_string(&format!("{:x}", hasher.finalize()));
    
        if p.setting.topic {
            enc.write_string(p.topic.as_deref().unwrap_or(""));
        }
    
        if !payload.is_empty() {
            enc.write_bytes(payload.as_bytes());
        }
    
        enc.to_uint8_array()
    }

    fn encode_subscribe_message(message: &dyn Any) -> Vec<u8> {
        let mut enc = Encoder::new();
        let p = message.downcast_ref::<SubscribeMessage>().unwrap();
        enc.write_uint8(p.setting);
        enc.write_string(&p.client_msg_no);
        enc.write_string(&p.channel_id);
        enc.write_uint8(p.channel_type);
        enc.write_uint8(p.action);
        enc.write_string(p.param.as_deref().unwrap_or(""));
        enc.to_uint8_array()
    }

    fn encode_recv_ack_message(message: &dyn Any) -> Vec<u8> {
        let mut enc = Encoder::new();
        let p = message.downcast_ref::<RecvAckMessage>().unwrap();
        let message_id_biguint = BigUint::parse_bytes(p.message_id.as_bytes(), 10).unwrap();
        enc.write_int64(&message_id_biguint);
        enc.write_int32(p.message_seq as i32);
        enc.to_uint8_array()
    }

    fn decode_connect_ack_message(f: &Packet<Box<dyn Any>>, decoder: &mut Decoder) -> Packet<Box<dyn Any>> {
        let mut p = ConnectAckMessage::new();

        if f.message_type == MesssageType::ConnectAck {
            p.server_version = decoder.read_byte();
            unsafe {
                SERVER_VERSION = p.server_version;
            }
            println!("服务器协议版本: {}", p.server_version);
        }

        p.time_diff = decoder.read_int64().into();
        p.reason_code = decoder.read_byte();
        p.server_key = decoder.read_string();
        p.salt = decoder.read_string();
        if p.server_version >= 4 {
            p.node_id = decoder.read_int64().into();
        }

        Packet::new(Box::new(p), MesssageType::ConnectAck)
    }

    fn decode_connect_message(f: &Packet<Box<dyn Any>>, decoder: &mut Decoder) -> Packet<Box<dyn Any>> {
        let mut p = ConnectMessage::new();

        p.version = decoder.read_byte();
        p.device_flag = decoder.read_byte();
        p.device_id = decoder.read_string();
        p.uid = decoder.read_string();
        p.token = decoder.read_string();
        p.client_timestamp = decoder.read_int64().to_u64().unwrap() as i64;
        p.client_key = decoder.read_string();
        Packet::new(Box::new(p), MesssageType::Connect)
    }

    fn decode_disconnect_message(f: &Packet<Box<dyn Any>>, decoder: &mut Decoder) -> Packet<Box<dyn Any>> {
        let mut p = DisconnectMessage::new();
        p.reason_code = decoder.read_byte();
        p.reason = decoder.read_string();
        Packet::new(Box::new(p), MesssageType::Disconnect)
    }

    fn decode_recv_message(f: &Packet<Box<dyn Any>>, decoder: &mut Decoder) -> Packet<Box<dyn Any>> {
        let mut p = RecvMessage::new();

        p.setting = Setting::from_uint8(decoder.read_byte());
        p.msg_key = decoder.read_string();
        p.from_uid = decoder.read_string();
        p.channel_id = decoder.read_string();
        p.channel_type = decoder.read_byte();
        if unsafe { SERVER_VERSION } >= 3 {
            p.expire = Some(decoder.read_int32());
        }
        p.client_msg_no = decoder.read_string();
        if p.setting.stream_on() {
            p.stream_no = decoder.read_string();
            p.stream_seq = decoder.read_int32();
            p.stream_flag = decoder.read_byte().into();
        }
        p.message_id = decoder.read_int64().to_string();
        p.message_seq = decoder.read_int32();
        p.timestamp = decoder.read_int32();
        if p.setting.topic {
            p.topic = Some(decoder.read_string());
        }
        p.payload = decoder.read_remaining();
        Packet::new(Box::new(p), MesssageType::Recv)
    }

    fn decode_send_ack_message(
        f: &Packet<Box<dyn Any>>,
        decoder: &mut Decoder,
    ) -> Packet<Box<dyn Any>> {
        let mut p = SendAckMessage::new();
        p.message_id = decoder.read_int64().into();
        p.client_seq = decoder.read_int32();
        p.message_seq = decoder.read_int32();
        p.reason_code = decoder.read_byte();
        Packet::new(Box::new(p), MesssageType::SendAck)
    }

    fn decode_subscribe_ack_message(f: &Packet<Box<dyn Any>>, decoder: &mut Decoder) -> Packet<Box<dyn Any>> {
        let mut p = SubscribeAckMessage::new();

        p.client_msg_no = decoder.read_string();
        p.channel_id = decoder.read_string();
        p.channel_type = decoder.read_byte();
        p.action = decoder.read_byte();
        p.reason_code = decoder.read_byte();
        Packet::new(Box::new(p), MesssageType::SubscribeAck)
    }

    // 编码头部
    fn encode_framer(f: &Packet<Box<dyn Any>>, remaining_length: usize) -> Vec<u8> {
        if f.message_type == MesssageType::Ping || f.message_type == MesssageType::Pong {
            return vec![(f.message_type as u8) << 4];
        }
        let mut headers = Vec::new();
        let type_and_flags = (Protocol::encode_bool(f.dup) << 3)
            | (Protocol::encode_bool(f.sync_once) << 2)
            | (Protocol::encode_bool(f.reddot) << 1)
            | Protocol::encode_bool(f.no_persist);
        headers.push((f.message_type as u8) << 4 | type_and_flags);
        let vlen = Protocol::encode_variable_length(remaining_length);
        headers.extend(vlen);
        headers
    }

    fn decode_framer(decoder: &mut Decoder) -> Packet<Box<dyn Any>> {
        let b = decoder.read_byte();
        let mut f = Packet {
            no_persist: (b & 0x01) > 0,
            reddot: ((b >> 1) & 0x01) > 0,
            sync_once: ((b >> 2) & 0x01) > 0,
            dup: ((b >> 3) & 0x01) > 0,
            remaining_length: 0,
            message_type: MesssageType::Reserved,
            message_object: Box::new(()) as Box<dyn Any>,
        };
        f.message_type = unsafe { std::mem::transmute(b >> 4) };
        if f.message_type != MesssageType::Ping && f.message_type != MesssageType::Pong {
            f.remaining_length = decoder.read_variable_length() as usize;
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

impl<T: Any> Packet<T> {
    pub fn as_any(&self) -> &dyn Any {
        &self.message_object
    }
}
