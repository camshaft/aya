use std::{net::UdpSocket, os::fd::AsRawFd, time::Duration};

use aya::{
    include_bytes_aligned,
    maps::{Array, CpuMap, XskMap},
    programs::{Xdp, XdpFlags},
    Bpf,
};
use object::{Object, ObjectSection, ObjectSymbol, SymbolSection};
use xsk_rs::{
    config::{LibbpfFlags, SocketConfigBuilder},
    Socket, Umem,
};

use super::integration_test;

#[integration_test(netns)]
fn af_xdp() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/release/redirect");
    let mut bpf = Bpf::load(bytes).unwrap();
    let mut socks: XskMap<_> = bpf.take_map("SOCKS").unwrap().try_into().unwrap();

    let xdp: &mut Xdp = bpf
        .program_mut("redirect_sock")
        .unwrap()
        .try_into()
        .unwrap();
    xdp.load().unwrap();
    xdp.attach("lo", XdpFlags::default()).unwrap();

    let (umem, mut descs) = Umem::new(Default::default(), 32.try_into().unwrap(), false).unwrap();
    let sk_cfg = SocketConfigBuilder::new()
        .libbpf_flags(LibbpfFlags::XSK_LIBBPF_FLAGS_INHIBIT_PROG_LOAD)
        .build();
    let (_tx, mut rx, fq_cq) = Socket::new(sk_cfg, &umem, &"lo".parse().unwrap(), 0).unwrap();
    let (mut fq, _cq) = fq_cq.unwrap();
    socks.set(0, rx.fd().as_raw_fd(), 0).unwrap();

    // SAFETY: descs are from the same umem as the socket is tied to
    // (valid for all further unsafe)
    unsafe { fq.produce(&descs) };

    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    sock.send_to(b"hello AF_XDP", "127.0.0.1:1777").unwrap();

    let n = unsafe { rx.consume(&mut descs) };
    assert_eq!(n, 1);

    let data = unsafe { umem.data(&descs[0]) };
    let buf = data.contents();
    let (eth, buf) = buf.split_at(14);
    assert_eq!(eth[12..14], [0x08, 0x00]); // IP
    let (ip, buf) = buf.split_at(20);
    assert_eq!(ip[9], 17); // UDP
    let (udp, payload) = buf.split_at(8);
    assert_eq!(&udp[0..2], port.to_be_bytes().as_slice()); // Source
    assert_eq!(&udp[2..4], 1777u16.to_be_bytes().as_slice()); // Dest
    assert_eq!(payload, b"hello AF_XDP");
}

#[integration_test]
fn prog_sections() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/release/xdp_sec");
    let obj_file = object::File::parse(bytes).unwrap();

    assert!(has_symbol(&obj_file, "xdp", "xdp_plain"));
    assert!(has_symbol(&obj_file, "xdp/named", "xdp_named"));
    assert!(has_symbol(&obj_file, "xdp.frags", "xdp_frags"));
    assert!(has_symbol(
        &obj_file,
        "xdp.frags/named_frags",
        "xdp_named_frags"
    ));
    assert!(has_symbol(&obj_file, "xdp/cpumap", "xdp_cpumap"));
    assert!(has_symbol(&obj_file, "xdp/devmap", "xdp_devmap"));
    assert!(has_symbol(
        &obj_file,
        "xdp/cpumap/cpumap_named",
        "xdp_cpumap_named"
    ));
    assert!(has_symbol(
        &obj_file,
        "xdp/devmap/devmap_named",
        "xdp_devmap_named"
    ));
    assert!(has_symbol(
        &obj_file,
        "xdp.frags/cpumap/frags_cm_named",
        "xdp_frags_cm_named"
    ));
    assert!(has_symbol(
        &obj_file,
        "xdp.frags/devmap/frags_dm_named",
        "xdp_frags_dm_named"
    ));
}

fn has_symbol(obj_file: &object::File, sec_name: &str, sym_name: &str) -> bool {
    let sec = obj_file.section_by_name(sec_name).expect(sec_name);
    let sec = SymbolSection::Section(sec.index());
    obj_file
        .symbols()
        .any(|sym| sym.section() == sec && sym.name() == Ok(sym_name))
}

#[integration_test]
fn map_load() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/release/xdp_sec");
    let bpf = Bpf::load(bytes).unwrap();

    bpf.program("xdp").unwrap();
    bpf.program("named").unwrap();
    bpf.program("xdp.frags").unwrap();
    bpf.program("named_frags").unwrap();
    bpf.program("cpumap").unwrap();
    bpf.program("devmap").unwrap();
    bpf.program("cpumap_named").unwrap();
    bpf.program("devmap_named").unwrap();
    bpf.program("frags_cm_named").unwrap();
    bpf.program("frags_cm_named").unwrap();
}

#[integration_test(netns)]
fn cpumap_chain() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/release/redirect");
    let mut bpf = Bpf::load(bytes).unwrap();

    // Load our cpumap and our canary map
    let mut cpus: CpuMap<_> = bpf.take_map("CPUS").unwrap().try_into().unwrap();
    let hits: Array<_, u32> = bpf.take_map("HITS").unwrap().try_into().unwrap();

    let xdp_chain_fd = {
        // Load the chained program to run on the target CPU
        let xdp: &mut Xdp = bpf
            .program_mut("redirect_cpu_chain")
            .unwrap()
            .try_into()
            .unwrap();
        xdp.load().unwrap();
        xdp.fd().unwrap()
    };
    cpus.set(0, 2048, Some(xdp_chain_fd), 0).unwrap();

    // Load the main program
    let xdp: &mut Xdp = bpf.program_mut("redirect_cpu").unwrap().try_into().unwrap();
    xdp.load().unwrap();
    xdp.attach("lo", XdpFlags::default()).unwrap();

    let sock = UdpSocket::bind("127.0.0.1:1777").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(1)))
        .unwrap();
    sock.send_to(b"hello cpumap", "127.0.0.1:1777").unwrap();

    // Read back the packet to ensure it wenth through the entire network stack, including our two
    // probes.
    let mut buf = vec![0u8; 1000];
    let n = sock.recv(&mut buf).unwrap();

    assert_eq!(&buf[..n], b"hello cpumap");
    assert_eq!(hits.get(&0, 0).unwrap(), 1);
    assert_eq!(hits.get(&1, 0).unwrap(), 1);
}
