#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action::XDP_PASS, macros::xdp, programs::XdpContext};

macro_rules! probe {
    ($name:ident, ($($arg:ident = $value:literal),*) ) => {
        #[xdp($($arg = $value),*)]
        pub fn $name(_ctx: XdpContext) -> u32 {
            XDP_PASS
        }
    };
}

probe!(xdp_plain, ());
probe!(xdp_named, (name = "named"));
probe!(xdp_frags, (frags = "true"));
probe!(xdp_named_frags, (name = "named_frags", frags = "true"));
probe!(xdp_cpumap, (map = "cpumap"));
probe!(xdp_devmap, (map = "devmap"));
probe!(xdp_cpumap_named, (name = "cpumap_named", map = "cpumap"));
probe!(xdp_devmap_named, (name = "devmap_named", map = "devmap"));
probe!(
    xdp_frags_cm_named,
    (name = "frags_cm_named", frags = "true", map = "cpumap")
);
probe!(
    xdp_frags_dm_named,
    (name = "frags_dm_named", frags = "true", map = "devmap")
);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
