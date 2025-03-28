use aya::{
    maps::AsyncPerfEventArray,
    util::online_cpus,
    Ebpf,
};
use bytes::BytesMut;
use waoo::read_event;
use waoo_common::OpenLog;

use crate::args;
use crate::program;

pub async fn opensnoop(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    program::attach_program(args::Commands::Opensnoop {}, ebpf);

    let mut events =
        AsyncPerfEventArray::try_from(ebpf.take_map("open_events").ok_or(()).unwrap())?;
    println!("Tracing open syscalls... Hit Ctrl-C to end.");
    println!(
        "{:6} {:16} {:4} {:3} {}",
        "PID", "COMM", "FD", "ERR", "FILENAME"
    );
    for cpu_id in online_cpus().map_err(|e| e.1)? {
        let buf = events.open(cpu_id, None)?;
        tokio::spawn(async move {
            read_event(cpu_id, buf, |event: &BytesMut| -> anyhow::Result<()> {
                let ptr = event.as_ptr() as *const OpenLog;
                let data = unsafe { ptr.read_unaligned() };
                let comm = cstr_slice_2_rstr(&data.comm);
                let filename = cstr_slice_2_rstr(&data.filename);
                println!(
                    "{:>6} {:>16} {:>4} {:>3} {}",
                    data.pid, comm, data.fd, data.errno, filename,
                );
                Ok(())
            }).await
        });
    }

    Ok(())
}

fn cstr_slice_2_rstr(cchr: &[u8]) -> String {
    String::from_utf8_lossy(cchr).into_owned()
}

