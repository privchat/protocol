extern crate num_bigint;
extern crate num_traits;

use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;

pub struct Encoder {
    w: Vec<u8>,
    d32: BigUint,
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            w: Vec::new(),
            d32: BigUint::from(4294967296u64),
        }
    }

    pub fn write_byte(&mut self, b: u8) {
        self.w.push(b);
    }

    pub fn write_bytes(&mut self, b: &[u8]) {
        self.w.extend_from_slice(b);
    }

    pub fn write_int64(&mut self, b: &BigUint) {
        let b1 = (b / &self.d32).to_u64().unwrap();
        let b2 = (b % &self.d32).to_u64().unwrap();

        self.w.push(((b1 >> 24) & 0xff) as u8);
        self.w.push(((b1 >> 16) & 0xff) as u8);
        self.w.push(((b1 >> 8) & 0xff) as u8);
        self.w.push((b1 & 0xff) as u8);

        self.w.push(((b2 >> 24) & 0xff) as u8);
        self.w.push(((b2 >> 16) & 0xff) as u8);
        self.w.push(((b2 >> 8) & 0xff) as u8);
        self.w.push((b2 & 0xff) as u8);
    }

    pub fn write_int32(&mut self, b: i32) {
        self.w.push((b >> 24) as u8);
        self.w.push((b >> 16) as u8);
        self.w.push((b >> 8) as u8);
        self.w.push((b & 0xff) as u8);
    }

    pub fn write_uint8(&mut self, b: u8) {
        self.w.push(b);
    }

    pub fn write_int16(&mut self, b: i16) {
        self.w.push((b >> 8) as u8);
        self.w.push((b & 0xff) as u8);
    }

    pub fn write_string(&mut self, s: &str) {
        if !s.is_empty() {
            let str_array = self.string_to_uint(s);
            self.write_int16(str_array.len() as i16);
            self.write_bytes(&str_array);
        } else {
            self.write_int16(0);
        }
    }

    fn string_to_uint(&self, str: &str) -> Vec<u8> {
        let string = str.encode_utf16().collect::<Vec<u16>>();
        let mut uint_array = Vec::new();
        for char_code in string {
            uint_array.push((char_code & 0xff) as u8);
            uint_array.push((char_code >> 8) as u8);
        }
        uint_array
    }

    pub fn to_uint8_array(&self) -> Vec<u8> {
        self.w.clone()
    }
}
