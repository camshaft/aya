use std::{net::UdpSocket, os::fd::AsRawFd};

use aya::{
    include_bytes_aligned,
    maps::XskMap,
    programs::{Xdp, XdpFlags},
    Bpf,
};
use xsk_rs::{
    config::{LibbpfFlags, SocketConfigBuilder},
    Socket, Umem,
};

use super::{integration_test, IntegrationTest};

#[integration_test]
fn af_xdp() {
    let bytes = include_bytes_aligned!("../../../../target/bpfel-unknown-none/debug/redirect");
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
