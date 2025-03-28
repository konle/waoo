#![no_std]
pub const NAME_MAX_LEN:usize = 128;
pub const COMM_MAX_LEN:usize = 16;
pub struct OpenLog {
    pub filename: [u8;NAME_MAX_LEN],
    pub pid: u32,
    pub errno: u64,
    pub comm: [u8;COMM_MAX_LEN],
    pub fd: u64,
}


pub struct KillLog{
    pub nsec:u64,
    pub killer: u32,
    pub pid:u32,
    pub comm: [u8;COMM_MAX_LEN],
    pub sig:u64,
    pub errno: u64,
}