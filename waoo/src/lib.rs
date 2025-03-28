use aya::maps::{perf::AsyncPerfEventArrayBuffer, MapData};
use bytes::BytesMut;
use log::warn;

pub async fn read_event(
    _cpu_id: u32,
    mut buf:  AsyncPerfEventArrayBuffer<MapData>,
    call: fn (&BytesMut) -> anyhow::Result<()>,
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
