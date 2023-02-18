//! An array of network devices.

use crate::{
    maps::{check_bounds, check_kv_size, IterableMap, MapData, MapError},
    sys::{bpf_map_lookup_elem, bpf_map_update_elem},
};

/// An array of network devices.
///
/// XDP programs can use this map to redirect to other network
/// devices.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 4.14.
///
/// # Examples
/// ```no_run
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::maps::xdp::DevMap;
///
/// let mut devmap = DevMap::try_from(bpf.map_mut("IFACES").unwrap())?;
/// let source = 32u32;
/// let dest = 42u32;
/// devmap.set(source, dest, 0);
///
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_DEVMAP")]
pub struct DevMap<T> {
    inner: T,
}

impl<T: AsRef<MapData>> DevMap<T> {
    pub(crate) fn new(map: T) -> Result<DevMap<T>, MapError> {
        let data = map.as_ref();
        check_kv_size::<u32, u32>(data)?;

        let _fd = data.fd_or_err()?;

        Ok(DevMap { inner: map })
    }

    /// Returns the number of elements in the array.
    ///
    /// This corresponds to the value of `bpf_map_def::max_entries` on the eBPF side.
    pub fn len(&self) -> u32 {
        self.inner.as_ref().obj.max_entries()
    }

    /// Returns the value stored at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get(&self, index: u32, flags: u64) -> Result<u32, MapError> {
        let data = self.inner.as_ref();
        check_bounds(data, index)?;
        let fd = data.fd_or_err()?;

        let value = bpf_map_lookup_elem(fd, &index, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                io_error,
            }
        })?;
        value.ok_or(MapError::KeyNotFound)
    }

    /// An iterator over the elements of the array. The iterator item type is `Result<u32,
    /// MapError>`.
    pub fn iter(&self) -> impl Iterator<Item = Result<u32, MapError>> + '_ {
        (0..self.len()).map(move |i| self.get(i, 0))
    }
}

impl<T: AsMut<MapData>> DevMap<T> {
    /// Sets the value of the element at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_update_elem` fails.
    pub fn set(&mut self, index: u32, value: u32, flags: u64) -> Result<(), MapError> {
        let data = self.inner.as_mut();
        check_bounds(data, index)?;
        let fd = data.fd_or_err()?;
        bpf_map_update_elem(fd, Some(&index), &value, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_update_elem".to_owned(),
                io_error,
            }
        })?;
        Ok(())
    }
}

impl<T: AsRef<MapData>> IterableMap<u32, u32> for DevMap<T> {
    fn map(&self) -> &MapData {
        self.inner.as_ref()
    }

    fn get(&self, key: &u32) -> Result<u32, MapError> {
        self.get(*key, 0)
    }
}
