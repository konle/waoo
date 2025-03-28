use aya::{maps::AsyncPerfEventArray, util::online_cpus, Ebpf};
use bytes::BytesMut;
use waoo::read_event;
use waoo_common::KillLog;

use crate::args;
use crate::program;

pub async fn killsnoop(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    program::attach_program(args::Commands::Killsnoop {}, ebpf);

    let mut events =
        AsyncPerfEventArray::try_from(ebpf.take_map("kill_events").ok_or(()).unwrap())?;
    println!("Tracing kill syscalls... Hit Ctrl-C to end.");
    println!(
        "{:6} {:16} {:4} {:3} {}",
        "KILLER", "COMM", "SIG", "PID", "RET"
    );
    for cpu_id in online_cpus().map_err(|e| e.1)? {
        let buf = events.open(cpu_id, None)?;
        tokio::spawn(async move {
            read_event(cpu_id, buf, |event: &BytesMut| -> anyhow::Result<()> {
                let ptr = event.as_ptr() as *const KillLog;
                let data = unsafe { ptr.read_unaligned() };
                let comm = String::from_utf8_lossy(&data.comm).into_owned();
                println!(
                    "{:>6} {:>16} {:>4} {:>3} {}",
                    data.killer, comm, data.sig, data.pid, data.errno,
                );
                Ok(())
            })
            .await
        });
    }
    Ok(())
}
