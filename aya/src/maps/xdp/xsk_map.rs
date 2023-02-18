//! An array of AF_XDP sockets.

use std::os::unix::prelude::{AsRawFd, RawFd};

use crate::{
    maps::{check_bounds, check_kv_size, MapData, MapError},
    sys::bpf_map_update_elem,
};

/// An array of AF_XDP sockets.
///
/// XDP programs can use this map to redirect packets to a target
/// AF_XDP socket using the `XDP_REDIRECT` action.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.18.
///
/// # Examples
/// ```no_run
/// # let mut bpf = aya::Bpf::load(&[])?;
/// # let socket_fd = 1;
/// use aya::maps::XskMap;
///
/// let mut xskmap = XskMap::try_from(bpf.map_mut("SOCKETS").unwrap())?;
/// // socket_fd is the RawFd of an AF_XDP socket
/// xskmap.set(0, socket_fd, 0);
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_XSKMAP")]
pub struct XskMap<T> {
    inner: T,
}

impl<T: AsRef<MapData>> XskMap<T> {
    pub(crate) fn new(map: T) -> Result<XskMap<T>, MapError> {
        let data = map.as_ref();
        check_kv_size::<u32, RawFd>(data)?;

        let _fd = data.fd_or_err()?;

        Ok(XskMap { inner: map })
    }

    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.inner.as_ref().obj.max_entries()
    }
}

impl<T: AsMut<MapData>> XskMap<T> {
    /// Sets the value of the element at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set<V: AsRawFd>(&mut self, index: u32, value: V, flags: u64) -> Result<(), MapError> {
        let data = self.inner.as_mut();
        check_bounds(data, index)?;
        let fd = data.fd_or_err()?;
        bpf_map_update_elem(fd, Some(&index), &value.as_raw_fd(), flags).map_err(
            |(_, io_error)| MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                io_error,
            },
        )?;
        Ok(())
    }
}
