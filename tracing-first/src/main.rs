use aya::programs::UProbe;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use tokio::{signal, task};
use bytes::BytesMut;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long)]
    pid: Option<i32>,
}

use aya::maps::AsyncPerfEventArray;
use tracing_first_common::DnsLog;
use std::convert::TryFrom;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();


    let ip = 2908488267u32;
    let ip = ip.to_le_bytes();
    let ip_addr = std::net::Ipv4Addr::try_from(ip).unwrap();
    println!("ip_addr: {:?}", ip_addr);


    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tracing-first"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tracing-first"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    //let _latency: HashMap<_, u32, u64> = HashMap::try_from(bpf.map_mut("LATENCY").unwrap()).unwrap();

    let program: &mut UProbe = bpf.program_mut("tracing_first").unwrap().try_into()?;
    program.load()?;
    program.attach(
        Some("getaddrinfo"),
        0,
        "/nix/store/whypqfa83z4bsn43n4byvmw80n4mg3r8-glibc-2.37-45/lib/libc.so.6",
        opt.pid,
    )?;

    let retprogram: &mut UProbe = bpf.program_mut("tracing_uretprobe").unwrap().try_into()?;
    retprogram.load()?;
    retprogram.attach(
        Some("getaddrinfo"),
        0,
        "/nix/store/whypqfa83z4bsn43n4byvmw80n4mg3r8-glibc-2.37-45/lib/libc.so.6",
        opt.pid,
    )?;


    let mut perf_array =
        AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    for cpu_id in online_cpus()? {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for buf in buffers.iter_mut().take(events.read) {
                    let ptr = buf.as_ptr() as *const DnsLog;
                    let data = unsafe { ptr.read_unaligned() };

                    let node = std::str::from_utf8(&data.node).unwrap();
                    let duration = std::time::Duration::from_nanos(data.duration);
                    let ip = std::net::Ipv4Addr::from((data.ip as u32).to_le_bytes());
                    let port = data.port;
                    info!("node: {}, duration: {:?}, ip: {}, port: {}", node, duration, ip, port);

                }
            }
        });
    }



    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");


    Ok(())
}
