use num_bigint::BigInt;
use std::any::Any;

static mut SERVER_VERSION: u8 = 0; // 服务端返回的协议版本

// 保留位
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum PacketType {
    Reserved = 0,
    Connect = 1,    // 客户端请求连接到服务器(c2s)
    ConnectAck = 2, // 服务端收到连接请求后确认的报文(s2c)
    Send = 3,       // 发送消息(c2s)
    SendAck = 4,    // 收到消息确认的报文(s2c)
    Recv = 5,       // 收取消息(s2c)
    RecvAck = 6,    // 收取消息确认(c2s)
    Ping = 7,       // ping请求
    Pong = 8,       // 对ping请求的相应
    Disconnect = 9, // 请求断开连接
    Sub = 10,       // 订阅
    SubAck = 11,    // 订阅确认
}

// 设置
#[derive(Clone)]
pub struct Setting {
    pub receipt_enabled: bool, // 消息回执是否开启
    pub topic: bool,           // 是否存在话题
    pub stream_on: bool,
    pub stream_no: String, // 流号
}

impl Setting {
    pub fn new() -> Self {
        Self {
            receipt_enabled: false,
            topic: false,
            stream_on: false,
            stream_no: String::new(),
        }
    }

    pub fn set_stream_no(&mut self, v: String) {
        if !v.is_empty() {
            self.stream_on = true;
        } else {
            self.stream_on = false;
        }
        self.stream_no = v;
    }

    pub fn stream_no(&self) -> &str {
        &self.stream_no
    }

    pub fn stream_on(&self) -> bool {
        self.stream_on
    }

    pub fn to_uint8(&self) -> u8 {
        (self.bool_to_int(self.receipt_enabled) << 7)
            | (self.bool_to_int(self.topic) << 3)
            | (self.bool_to_int(self.stream_on) << 2)
    }

    pub fn from_uint8(v: u8) -> Self {
        let mut setting = Self::new();
        setting.receipt_enabled = (v >> 7 & 0x01) > 0;
        setting.topic = (v >> 3 & 0x01) > 0;
        setting.stream_on = (v >> 2 & 0x01) > 0;
        setting
    }

    fn bool_to_int(&self, v: bool) -> u8 {
        if v {
            1
        } else {
            0
        }
    }
}

// 包
#[derive(Clone, Debug)]
pub struct Packet<T> {
    pub no_persist: bool,
    pub reddot: bool,
    pub sync_once: bool,
    pub dup: bool,
    pub remaining_length: usize,
    pub packet_type: PacketType,
    pub packet_object: T,
}

impl<T> Packet<T> {
    pub fn new(packet_object: T, packet_type: PacketType) -> Self {
        Self {
            no_persist: false,
            reddot: false,
            sync_once: false,
            dup: false,
            remaining_length: 0,
            packet_type,
            packet_object,
        }
    }

    pub fn from(&mut self, f: &Packet<T>) {
        self.no_persist = f.no_persist;
        self.reddot = f.reddot;
        self.sync_once = f.sync_once;
        self.dup = f.dup;
        self.remaining_length = f.remaining_length;
        self.packet_type = f.packet_type;
    }
}

// 连接包
#[derive(Debug)]
pub struct ConnectPacket {
    pub version: u8,           // 版本
    pub client_key: String,    // 客户端key
    pub device_id: String,     // 设备ID
    pub device_flag: u8,       // 设备标示
    pub client_timestamp: i64, // 客户端时间戳
    pub uid: String,           // 用户UID
    pub token: String,         // 用户token
}

impl ConnectPacket {
    pub fn new() -> Self {
        Self {
            version: 0,
            client_key: String::new(),
            device_id: String::new(),
            device_flag: 0,
            client_timestamp: 0,
            uid: String::new(),
            token: String::new(),
        }
    }

    pub fn create_packet(self) -> Packet<Box<dyn Any>> {
        Packet::new(Box::new(self), PacketType::Connect)
    }

    pub fn as_any(&self) -> &dyn Any {
        self
    }
}

// 连接回执包
pub struct ConnectAckPacket {
    pub server_version: u8, // 服务端版本
    pub server_key: String, // 通过客户端的RSA公钥加密的服务端DH公钥
    pub salt: String,       // salt
    pub time_diff: BigInt,  // 客户端时间与服务器的差值，单位毫秒
    pub reason_code: u8,    // 原因码
    pub node_id: BigInt,    // 节点ID
}

impl ConnectAckPacket {
    pub fn new() -> Self {
        Self {
            server_version: 0,
            server_key: String::new(),
            salt: String::new(),
            time_diff: BigInt::default(),
            reason_code: 0,
            node_id: BigInt::default(),
        }
    }

    pub fn create_packet(self) -> Packet<Self> {
        Packet::new(self, PacketType::ConnectAck)
    }
}

// 断开包
pub struct DisconnectPacket {
    pub reason_code: u8, // 原因码
    pub reason: String,  // 具体断开原因
}

impl DisconnectPacket {
    pub fn new() -> Self {
        Self {
            reason_code: 0,
            reason: String::new(),
        }
    }

    pub fn create_packet(self) -> Packet<Self> {
        Packet::new(self, PacketType::Disconnect)
    }
}

// 发送包
#[derive(Clone)]
pub struct SendPacket {
    pub setting: Setting, // 设置
    pub client_seq: u32,
    pub client_msg_no: String, // 客户端唯一消息编号（用于消息去重）
    pub stream_no: String,     // 流式编号
    pub channel_id: String,    // 频道ID
    pub channel_type: u8,      // 频道类型
    pub expire: Option<u32>,   // 消息过期时间
    pub from_uid: String,      // 发送UID
    pub topic: Option<String>,
    pub payload: Vec<u8>, // 负荷数据
}

impl SendPacket {
    pub fn new() -> Self {
        Self {
            setting: Setting::new(),
            client_seq: 0,
            client_msg_no: String::new(),
            stream_no: String::new(),
            channel_id: String::new(),
            channel_type: 0,
            expire: None,
            from_uid: String::new(),
            topic: None,
            payload: Vec::new(),
        }
    }

    pub fn create_packet(self) -> Packet<Self> {
        Packet::new(self, PacketType::Send)
    }

    pub fn verify_string(&self) -> String {
        let payload_str = String::from_utf8_lossy(&self.payload).to_string();
        format!(
            "{}{}{}{}{}",
            self.client_seq, self.client_msg_no, self.channel_id, self.channel_type, payload_str
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum StreamFlag {
    Start = 0,
    Ing = 1,
    End = 2,
}

impl From<u8> for StreamFlag {
    fn from(value: u8) -> Self {
        match value {
            0 => StreamFlag::Start,
            1 => StreamFlag::Ing,
            2 => StreamFlag::End,
            _ => panic!("Invalid value for StreamFlag"),
        }
    }
}

// 收消息包
pub struct RecvPacket {
    pub setting: Setting,        // 设置
    pub msg_key: String,         // 用于验证此消息是否合法（仿中间人篡改）
    pub message_id: String,      // 消息ID
    pub message_seq: u32,        // 消息序列号
    pub client_msg_no: String,   // 客户端唯一消息编号
    pub stream_no: String,       // 流式编号
    pub stream_seq: u32,         // 流式序列号
    pub stream_flag: StreamFlag, // 流式标示
    pub timestamp: u32,          // 消息时间戳
    pub channel_id: String,      // 频道ID
    pub channel_type: u8,        // 频道类型
    pub expire: Option<u32>,     // 消息过期时间
    pub topic: Option<String>,   // topic
    pub from_uid: String,        // 发送者UID
    pub payload: Vec<u8>,        // 负荷数据
}

impl RecvPacket {
    pub fn new() -> Self {
        Self {
            setting: Setting::new(),
            msg_key: String::new(),
            message_id: String::new(),
            message_seq: 0,
            client_msg_no: String::new(),
            stream_no: String::new(),
            stream_seq: 0,
            stream_flag: StreamFlag::Start,
            timestamp: 0,
            channel_id: String::new(),
            channel_type: 0,
            expire: None,
            topic: None,
            from_uid: String::new(),
            payload: Vec::new(),
        }
    }
    pub fn create_packet(self) -> Packet<Self> {
        Packet::new(self, PacketType::Recv)
    }

    pub fn verify_string(&self) -> String {
        let payload_str = String::from_utf8_lossy(&self.payload).to_string();
        format!(
            "{}{}{}{}{}{}{}{}",
            self.message_id,
            self.message_seq,
            self.client_msg_no,
            self.timestamp,
            self.from_uid,
            self.channel_id,
            self.channel_type,
            payload_str
        )
    }
}

// ping
pub struct PingPacket;

impl PingPacket {
    pub fn new() -> Self {
        Self
    }

    pub fn create_packet(self) -> Packet<Self> {
        Packet::new(self, PacketType::Ping)
    }
}

// pong
pub struct PongPacket;

impl PongPacket {
    pub fn new() -> Self {
        Self
    }
    pub fn create_packet(self) -> Packet<Self> {
        Packet::new(self, PacketType::Pong)
    }
}

// 消息发送回执
pub struct SendAckPacket {
    pub client_seq: u32,
    pub message_id: BigInt,
    pub message_seq: u32,
    pub reason_code: u8,
}

impl SendAckPacket {
    pub fn new() -> Self {
        Self {
            client_seq: 0,
            message_id: BigInt::default(),
            message_seq: 0,
            reason_code: 0,
        }
    }

    pub fn create_packet(self) -> Packet<Self> {
        Packet::new(self, PacketType::SendAck)
    }
}

// 收到消息回执给服务端的包
pub struct RecvAckPacket {
    pub message_id: String,
    pub message_seq: u32,
}

impl RecvAckPacket {
    pub fn new() -> Self {
        Self {
            message_id: String::new(),
            message_seq: 0,
        }
    }

    pub fn create_packet(self) -> Packet<Self> {
        Packet::new(self, PacketType::RecvAck)
    }
}

// 订阅包
pub struct SubPacket {
    pub setting: u8,           // 设置
    pub client_msg_no: String, // 客户端唯一消息编号
    pub channel_id: String,    // 频道ID
    pub channel_type: u8,      // 频道类型
    pub action: u8,            // 0:订阅 1:取消订阅
    pub param: Option<String>, // 参数
}

impl SubPacket {
    pub fn new() -> Self {
        Self {
            setting: 0,
            client_msg_no: String::new(),
            channel_id: String::new(),
            channel_type: 0,
            action: 0,
            param: None,
        }
    }
    pub fn create_packet(self) -> Packet<Self> {
        Packet::new(self, PacketType::Sub)
    }
}

// 订阅确认包
pub struct SubAckPacket {
    pub client_msg_no: String, // 客户端唯一消息编号
    pub channel_id: String,    // 频道ID
    pub channel_type: u8,      // 频道类型
    pub action: u8,            // 0:订阅 1:取消订阅
    pub reason_code: u8,
}

impl SubAckPacket {
    pub fn new() -> Self {
        Self {
            client_msg_no: String::new(),
            channel_id: String::new(),
            channel_type: 0,
            action: 0,
            reason_code: 0,
        }
    }

    pub fn create_packet(self) -> Packet<Self> {
        Packet::new(self, PacketType::SubAck)
    }
}
