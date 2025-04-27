use std::net::{Ipv4Addr, Ipv6Addr};

use aya::maps::{perf::AsyncPerfEventArrayBuffer, MapData};
use aya::{maps::AsyncPerfEventArray, util::online_cpus, Ebpf};
use bytes::BytesMut;
use chrono::{DateTime, Local};
use log::warn;

use waoo_common::{KillLog, TcpConnectLog, AF_INET};

pub mod args;
pub mod program;
pub async fn read_event(
    _cpu_id: u32,
    mut buf: AsyncPerfEventArrayBuffer<MapData>,
    call: fn(&BytesMut) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    let mut data = [bytes::BytesMut::with_capacity(1)];
    loop {
        let events = buf.read_events(&mut data).await;
        match events {
            Ok(events) => {
                for event in &data[..events.read] {
                    call(event)?;
                }
            }
            Err(e) => {
                warn!("failed to read event: {}", e);
            }
        }
    }
}

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

pub async fn tcpconnect(ebpf: &mut Ebpf) -> anyhow::Result<()> {
    println!("Tracing tcp connects... Hit Ctrl-C to end.");

    println!(
        "{:>20} {:>8} {:>16} {:>39} {:>6} {:>39} {:>6}",
        "TIME", "PID", "COMM", "SADDR", "SPORT", "DADDR", "DPORT"
    );
    program::attach_program(args::Commands::Tcpconnect {}, ebpf);
    let mut events = AsyncPerfEventArray::try_from(ebpf.take_map("tcp_events").ok_or(()).unwrap())?;
    for cpu_id in online_cpus().map_err(|e| e.1)? {
        let buf = events.open(cpu_id, None)?;
        tokio::spawn(async move {
            read_event(cpu_id, buf, |event: &BytesMut| -> anyhow::Result<()> {
                let ptr = event.as_ptr() as *const TcpConnectLog;
                let data = unsafe { ptr.read_unaligned() };
                let comm = String::from_utf8_lossy(&data.comm).into_owned();
                let dtime: DateTime<Local> =
                    DateTime::from_timestamp_nanos(data.nsec as i64).into();
                if data.af_net_version == AF_INET {
                    println!(
                        "{:>20} {:>8} {:>16} {:>39} {:>6} {:>39} {:>6}",
                        dtime.format("%Y-%m-%d %H:%M:%S"),
                        data.pid,
                        comm,
                        Ipv4Addr::from(data.ipv4_src),
                        data.lport,
                        Ipv4Addr::from(data.ipv4_dest),
                        data.dport,
                    );
                } else {
                    println!(
                        "{:>20} {:>8} {:>16} {:>39} {:>6} {:>39} {:>6}",
                        dtime.format("%Y-%m-%d %H:%M:%S"),
                        data.pid,
                        comm,
                        Ipv6Addr::from(data.ipv6_src),
                        data.lport,
                        Ipv6Addr::from(data.ipv6_dest),
                        data.dport,
                    );
                }

                Ok(())
            })
            .await
        });
    }

    Ok(())
}
