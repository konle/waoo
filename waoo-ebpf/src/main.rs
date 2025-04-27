#![no_std]
#![no_main]
use aya_ebpf::{
    macros::tracepoint,
    macros::kprobe,
    programs::ProbeContext,
    programs::TracePointContext,
};

use waoo_ebpf::{try_enter_kill, try_exit_kill, try_kprobe_tcp_connect, try_sys_enter_open};
use waoo_ebpf::try_sys_enter_openat;
use waoo_ebpf::try_sys_exit_open;


#[tracepoint]
pub fn trace_sys_exit_open(ctx: TracePointContext) -> u32 {
    match try_sys_exit_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn trace_sys_exit_openat(ctx: TracePointContext) -> u32 {
    match try_sys_exit_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn trace_sys_enter_open(ctx: TracePointContext) -> u32 {
    match try_sys_enter_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn trace_sys_enter_openat(ctx: TracePointContext) -> u32 {
    match try_sys_enter_openat(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn trace_enter_kill(ctx: TracePointContext)->u32{
    match try_enter_kill(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[tracepoint]
pub fn trace_exit_kill(ctx: TracePointContext)->u32{
    match try_exit_kill(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

#[kprobe]
pub fn kprobe_tcp_connect(ctx: ProbeContext) -> u32 {
    match try_kprobe_tcp_connect(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret.try_into().unwrap_or(1),
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
