#![no_std]


pub struct DnsLog {
    pub duration: u64,
    pub node: [u8; 32],
    pub ip: u64,
    pub port: u64,
}
