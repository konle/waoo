#![no_std]
#![no_main]
use aya_ebpf::{
    helpers,
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    EbpfContext,
};

use waoo_ebpf::try_sys_enter_open;
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



#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
