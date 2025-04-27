// #![no_std]
// #![no_main]
use aya_ebpf::{
     helpers::{self, bpf_probe_read_kernel}, macros::map, maps::{HashMap, PerfEventArray}, programs::{ ProbeContext, TracePointContext}, EbpfContext
};
use waoo_common::{KillLog, OpenLog, TcpConnectLog, COMM_MAX_LEN, NAME_MAX_LEN};

use crate::{read_at, sock_binding::{sock, sock_common}};




#[map]
static OPEN_MAPS: HashMap<u64, [u8; NAME_MAX_LEN]> = HashMap::with_max_entries(1024, 0);

#[map(name = "open_events")]
static OPEN_EVENTS: PerfEventArray<OpenLog> = PerfEventArray::new(0);

#[map(name = "kill_events")]
static KILL_EVENTS: PerfEventArray<KillLog> = PerfEventArray::new(0);

// (pid, sig)
#[map]
static KILL_MAPS: HashMap<u64, (u64, u64)> = HashMap::with_max_entries(1024, 0);
#[map(name = "tcp_events")]
static TCP_EVENTS: PerfEventArray<TcpConnectLog> = PerfEventArray::new(0);

/**
 *
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_open/format
name: sys_exit_open
ID: 768
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret

sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_openat/format
name: sys_exit_openat
ID: 766
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret

 */
pub fn try_sys_exit_open(ctx: TracePointContext) -> Result<u32, u32> {
    let tid: u64 = helpers::bpf_get_current_pid_tgid();
    let ret: i64 = read_at(&ctx, 16)?;
    let errno: u64 = if ret >= 0 { 0 } else { -ret as u64 };
    let filename = unsafe {
        OPEN_MAPS
            .get(&tid)
            .ok_or(0u32)
            .map_err(|e| -> u32 {
                // helpers::bpf_printk!(b"failed to get tid=%lu .......", tid);
                e
            })?
            .clone()
    };
    let _ = OPEN_MAPS.remove(&tid);
    let data = OpenLog {
        errno,
        filename,
        pid: ctx.pid(),
        fd: ret as u64,
        comm: ctx.command().map_err(|e| e as u32)?,
    };
    OPEN_EVENTS.output(&ctx, &data, 0);
    let _ = OPEN_MAPS.remove(&tid);
    Ok(0)
}

/**
 *
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
name: sys_enter_open
ID: 769
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:const char * filename;    offset:16;      size:8; signed:0;
        field:int flags;        offset:24;      size:8; signed:0;
        field:umode_t mode;     offset:32;      size:8; signed:0;

print fmt: "filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))

 */
pub fn try_sys_enter_open(ctx: TracePointContext) -> Result<u32, u32> {
    let tid: u64 = helpers::bpf_get_current_pid_tgid();
    let filename_ptr: *const u8 = read_at(&ctx, 16).map_err(|e| e)?;
    let mut filename: [u8; NAME_MAX_LEN] = [0; NAME_MAX_LEN];
    unsafe {
        let _ = helpers::bpf_probe_read_user_str_bytes(filename_ptr, &mut filename)
            .map_err(|e| e as u32)?;
    };
    OPEN_MAPS.insert(&tid, &filename, 0).map_err(|e| e as u32)?;
    Ok(0)
}

/**
 *
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
name: sys_enter_openat
ID: 767
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int dfd;  offset:16;      size:8; signed:0;
        field:const char * filename;    offset:24;      size:8; signed:0;
        field:int flags;        offset:32;      size:8; signed:0;
        field:umode_t mode;     offset:40;      size:8; signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))


 */
pub fn try_sys_enter_openat(ctx: TracePointContext) -> Result<u32, u32> {
    let tid: u64 = helpers::bpf_get_current_pid_tgid();
    let filename_ptr: *const u8 = read_at(&ctx, 24).map_err(|e| e)?;
    let mut filename: [u8; NAME_MAX_LEN] = [0; NAME_MAX_LEN];
    unsafe {
        let _ = helpers::bpf_probe_read_user_str_bytes(filename_ptr, &mut filename)
            .map_err(|e| e as u32)?;
    };
    OPEN_MAPS.insert(&tid, &filename, 0).map_err(|e| e as u32)?;
    Ok(0)
}
/**
 * 
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_kill/format
name: sys_enter_kill
ID: 184
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:pid_t pid;        offset:16;      size:8; signed:0;
        field:int sig;  offset:24;      size:8; signed:0;

print fmt: "pid: 0x%08lx, sig: 0x%08lx", ((unsigned long)(REC->pid)), ((unsigned long)(REC->sig))

 */
pub fn try_enter_kill(ctx: TracePointContext)->Result<u32, u32>{
    let pid:u64 = read_at(&ctx, 16)?;
    let sig:u64 = read_at(&ctx, 24)?;
    let tid: u64 = helpers::bpf_get_current_pid_tgid();
    // info!(&ctx, "{} send {} signal to {}", sig, sig, pid);
    let _ = KILL_MAPS.insert(&tid, &(pid, sig), 0);
    Ok(0)
}

/**
sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_exit_kill/format
name: sys_exit_kill
ID: 183
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:long ret; offset:16;      size:8; signed:1;

print fmt: "0x%lx", REC->ret

 */
pub fn try_exit_kill(ctx: TracePointContext)->Result<u32, u32>{
    let killer = ctx.pid();
    let mut c = [0u8; COMM_MAX_LEN];
    c [0] = b'-';
    let comm = ctx.command().unwrap_or(c);
    let tid: u64 = helpers::bpf_get_current_pid_tgid();
    let (pid, sig) =unsafe {
        KILL_MAPS.get(&tid).ok_or(0u32).map_err(|e| e 
            )?
    };
    let data = KillLog{
        killer,
        pid: pid.clone() as u32,
        sig: sig.clone(),
        comm,
        nsec: unsafe {
            helpers::bpf_ktime_get_ns()
        },
        errno: read_at(&ctx, 16)?,
    };
    KILL_EVENTS.output(&ctx, &data, 0);
    let _ = KILL_MAPS.remove(&tid);
    Ok(0)
}

pub fn try_kprobe_tcp_connect(ctx: ProbeContext)->Result<u32, i64>{
    let sock: *mut sock = ctx.arg(0).ok_or(1u32)?;
    let sk_common = unsafe {
         bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)
    }?;
    // // 目的端口是大端需要转换
    // let dport = unsafe {
    //     sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport.swap_bytes()
    // };
    let event = TcpConnectLog{
        nsec: unsafe {
            helpers::bpf_ktime_get_tai_ns()
        },
        pid:ctx.pid(),
        ipv4_src: u32::from_be(unsafe{
            sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr
        }),
        ipv4_dest: u32::from_be(unsafe {
            sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr
        }),
        ipv6_src: unsafe {
            sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8
        },
        ipv6_dest: unsafe {
            sk_common.skc_v6_daddr.in6_u.u6_addr8
        },
        comm:ctx.command().unwrap_or([0u8; COMM_MAX_LEN]),
        dport:unsafe {
            sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport.swap_bytes()
        },
        lport:unsafe {
            sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num
        },
        af_net_version: sk_common.skc_family,
    };
    TCP_EVENTS.output(&ctx, &event, 0);
    Ok(0)
}