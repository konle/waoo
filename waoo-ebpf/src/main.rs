#![no_std]
#![no_main]
use aya_ebpf::{
    macros::tracepoint,
    programs::TracePointContext,
};

use waoo_ebpf::{try_enter_kill, try_exit_kill, try_sys_enter_open};
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

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
