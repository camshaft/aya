#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{CpuMap, DevMap, DevMapHash, XskMap},
    programs::XdpContext,
};

#[map]
static SOCKS: XskMap = XskMap::with_max_entries(1, 0);
#[map]
static DEVS: DevMap = DevMap::with_max_entries(1, 0);
#[map]
static DEVS_HASH: DevMapHash = DevMapHash::with_max_entries(1, 0);
#[map]
static CPUS: CpuMap = CpuMap::with_max_entries(1, 0);

#[xdp(name = "redirect_sock")]
pub fn redirect_sock(_ctx: XdpContext) -> u32 {
    SOCKS.redirect(0, xdp_action::XDP_ABORTED as u64)
}

#[xdp(name = "redirect_dev")]
pub fn redirect_dev(_ctx: XdpContext) -> u32 {
    DEVS.redirect(0, xdp_action::XDP_ABORTED as u64)
}

#[xdp(name = "redirect_dev_hash")]
pub fn redirect_dev_hash(_ctx: XdpContext) -> u32 {
    DEVS_HASH.redirect(10, xdp_action::XDP_ABORTED as u64)
}

#[xdp(name = "redirect_cpu")]
pub fn redirect_cpu(_ctx: XdpContext) -> u32 {
    CPUS.redirect(0, xdp_action::XDP_ABORTED as u64)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
