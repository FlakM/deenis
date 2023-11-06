#![no_std]
#![no_main]
use aya_bpf::helpers::bpf_get_current_pid_tgid;
use aya_bpf::helpers::bpf_probe_read;
use aya_bpf::helpers::bpf_probe_read_user;
use aya_bpf::helpers::bpf_probe_read_user_str;
use aya_bpf::helpers::bpf_probe_read_user_str_bytes;
use aya_bpf::helpers::gen::bpf_ktime_get_ns;
use aya_bpf::BpfContext;
use aya_bpf::{
    macros::map,
    macros::{uprobe, uretprobe},
    maps::HashMap,
    programs::ProbeContext,
};
use aya_log_ebpf::info;
use core::ffi::c_char;
use core::ffi::c_int;
use tracing_first_ebpf::generated::addrinfo;
use tracing_first_ebpf::generated::sockaddr_in;
use tracing_first_ebpf::generated::sockaddr;
use tracing_first_common::DnsLog;
use aya_bpf::maps::PerfEventArray;


#[map(name = "LATENCY")]
static mut LATENCY: HashMap<u32, CallMetadata> = HashMap::with_max_entries(1024, 0);

#[map(name = "EVENTS")]
static EVENTS: PerfEventArray<DnsLog> = PerfEventArray::with_max_entries(1024, 0);


#[uprobe]
pub fn tracing_first(ctx: ProbeContext) -> u32 {
    match try_tracing_first(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

pub struct CallMetadata {
    pub start: u64,
    pub _node: *const c_char,
    pub get_addr_ptr: *const *const addrinfo,
}

fn try_tracing_first(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let tid: u32 = bpf_get_current_pid_tgid() as u32;
        let now = bpf_ktime_get_ns();

        let addrinfo_ptr: *const *const addrinfo = ctx.arg(3).ok_or(1u32)?;

        let metadata = CallMetadata {
            start: now,
            _node: ctx.arg(0).unwrap(),
            get_addr_ptr: addrinfo_ptr,
        };

        let Ok(()) = LATENCY.insert(&tid, &metadata, 0_u64) else {
            info!(&ctx, "failed to insert latency");
            return Err(0);
        };
    };
    Ok(0)
}

#[uretprobe]
pub fn tracing_uretprobe(ctx: ProbeContext) -> u32 {
    match try_tracing_uretprobe(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tracing_uretprobe(ctx: ProbeContext) -> Result<u32, u32> {
    unsafe {
        let tid: u32 = bpf_get_current_pid_tgid() as u32;
        let now = bpf_ktime_get_ns();

        let Some(CallMetadata {
            start,
            _node,
            get_addr_ptr,
        }) = LATENCY.get(&tid)
        else {
            info!(&ctx, "failed to get LATENCY element: {}", tid);
            return Err(1);
        };

        let latency = now - start;


        // read node string
        let mut node_buf = [0u8; 32];
        let node = bpf_probe_read_user_str(*_node as *const c_char as *const u8, &mut node_buf).map_err(|e| {
            info!(&ctx, "failed to read user node");
            e as u32
        })?;

        let addrinfo_ptr: *const addrinfo = {
            bpf_probe_read_user((*get_addr_ptr) as *const *const addrinfo).map_err(|e| {
                info!(&ctx, "failed to read user addrinfo 0");
                e as u32
            })?
        };

        let info: addrinfo = {
            bpf_probe_read_user(addrinfo_ptr as *const addrinfo).map_err(|e| {
                info!(&ctx, "failed to read user addrinfo 1");
                e as u32
            })?
        };

        let mut buf = [0u8; 128];


        let socket_len: u32 = info.ai_addrlen;
        let socket_addr: sockaddr = {
            bpf_probe_read_user(
                info.ai_addr as *const sockaddr,
            ).map_err(|e| {
                info!(&ctx, "failed to read ai_addr");
                e as u32
            })?
        };

        let socket = if socket_addr.sa_family == 2 {
            let socket4: sockaddr_in = {
                bpf_probe_read_user(
                    info.ai_addr as *const sockaddr_in,
                ).map_err(|e| {
                    info!(&ctx, "failed to read ai_addr");
                    e as u32
                })?
            };
            socket4
        } else {
            info!(&ctx, "not ipv4");
            return Err(1);
        };

        let ip = socket.sin_addr.s_addr as u32;
        let port = socket.sin_port as u32;


        let ret = LATENCY.remove(&tid);
        if ret.is_err() {
            info!(&ctx, "failed to delete latency");
            return Err(1);
        }

        let log = DnsLog {
            duration: latency,
            node: node_buf,
            ip: ip as u64,
            port: port as u64,
        };
        EVENTS.output(&ctx, &log, 0);   
    };

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
