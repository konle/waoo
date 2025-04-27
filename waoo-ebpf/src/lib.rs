#![no_std]

use aya_ebpf::programs::TracePointContext;

// This file exists to enable the library target.
mod open;
pub use open::try_sys_enter_open;
pub use open::try_sys_enter_openat;
pub use open::try_sys_exit_open;
pub use open::{try_enter_kill, try_exit_kill, try_kprobe_tcp_connect};
#[allow(clippy::all)]
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
#[rustfmt::skip]
mod sock_binding;

#[inline(always)] 
pub fn read_at<T>(ctx: &TracePointContext, offset: usize)->Result<T, u32>{
    unsafe {
        ctx.read_at(offset).map_err(|e|e as u32)
    }
}