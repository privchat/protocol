extern crate num_bigint;
extern crate num_traits;

use num_bigint::BigUint;
use num_traits::cast::ToPrimitive;
use std::str;

pub struct Decoder {
    data: Vec<u8>,
    offset: usize,
}

impl Decoder {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, offset: 0 }
    }

    pub fn size() -> usize {
        0
    }

    pub fn read_byte(&mut self) -> u8 {
        if self.offset >= self.data.len() {
            panic!(
                "index out of bounds: the len is {} but the index is {}",
                self.data.len(),
                self.offset
            );
        }
        let d = self.data[self.offset];
        self.offset += 1;
        d
    }

    pub fn read_num(&mut self, b: usize) -> BigUint {
        if self.offset + b > self.data.len() {
            panic!(
                "index out of bounds: the len is {} but the index is {}",
                self.data.len(),
                self.offset + b
            );
        }
        let data = &self.data[self.offset..self.offset + b];
        self.offset += b;
        let mut n = BigUint::from(0u32);
        for &byte in data {
            n = (n << 8) | BigUint::from(byte);
        }
        n
    }

    // 读取64bit的int数据（Rust没有原生的int64类型，所以这里只能用BigUint接受）
    pub fn read_int64(&mut self) -> BigUint {
        self.read_num(8)
    }

    pub fn read_int16(&mut self) -> u16 {
        self.read_num(2).to_u16().unwrap()
    }

    pub fn read_int32(&mut self) -> u32 {
        self.read_num(4).to_u32().unwrap()
    }

    pub fn read_string(&mut self) -> String {
        let len = self.read_int16() as usize;
        if len == 0 {
            return String::new();
        }
        let str_uint8_array = &self.data[self.offset..self.offset + len];
        self.offset += len;
        self.uint_to_string(str_uint8_array)
    }

    // 读取剩余的字节
    pub fn read_remaining(&mut self) -> Vec<u8> {
        let data = self.data[self.offset..].to_vec();
        self.offset = self.data.len();
        data
    }

    fn uint_to_string(&self, array: &[u8]) -> String {
        let encoded_string = str::from_utf8(array).unwrap();
        let decoded_string = encoded_string.to_string();
        decoded_string
    }

    pub fn read_variable_length(&mut self) -> usize {
        let mut multiplier = 0;
        let mut r_length = 0;
        while multiplier < 27 {
            let b = self.read_byte();
            r_length |= ((b & 127) as usize) << multiplier;
            if (b & 128) == 0 {
                break;
            }
            multiplier += 7;
        }
        r_length
    }
}
