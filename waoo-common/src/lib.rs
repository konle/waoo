#![no_std]
pub const NAME_MAX_LEN:usize = 128;
pub const COMM_MAX_LEN:usize = 16;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
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

pub struct TcpConnectLog{
    pub nsec:u64,
    pub pid:u32,
    pub ipv4_src: u32,
    pub ipv4_dest: u32,
    pub ipv6_src: [u8;16],
    pub ipv6_dest: [u8;16],
    pub comm: [u8;COMM_MAX_LEN],
    pub dport: u16,
    pub lport: u16,
    pub af_net_version: u16,
}