#![no_std]
//use crate::arch;
extern crate spin;
use lazy_static::lazy_static;
use hashbrown::HashMap;
extern crate alloc;
use alloc::vec::Vec;
lazy_static!{
    static ref DATABASE: spin::Mutex<HashMap<i32, Vec<u8>>> = spin::Mutex::new(HashMap::new());
}



pub fn set(idx: i32, val: &[u8]){
    let len: usize = val.len();
    //let data: &'static[u8] = &'static[0; len];
    let mut data: Vec<u8> = Vec::with_capacity(len);
    for i in val{data.push(*i);}
    //let v: &'static[u8] = val as &'static[u8];
    DATABASE.lock().insert(idx, data);
    //arch.output_message_buf(b"set {} at key {}", val, idx);
}

pub fn get(idx:i32) -> Vec<u8>{
    let val:  Vec<u8> = DATABASE.lock().get(&idx).unwrap().to_vec();
    //arch.output_message_buf(b"got {} from key {}", val, idx);
    return val;
}
