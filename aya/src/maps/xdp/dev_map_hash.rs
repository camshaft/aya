//! An hashmap of network devices.

use std::os::fd::AsRawFd;

use aya_obj::generated::{bpf_devmap_val, bpf_devmap_val__bindgen_ty_1};

use crate::{
    maps::{check_kv_size, hash_map, IterableMap, MapData, MapError, MapIter, MapKeys},
    sys::bpf_map_lookup_elem,
};

use super::dev_map::DevMapValue;

/// An hashmap of network devices.
///
/// XDP programs can use this map to redirect to other network
/// devices.
///
/// # Minimum kernel version
///
/// The minimum kernel version required to use this feature is 5.4.
///
/// # Examples
/// ```no_run
/// # let mut bpf = aya::Bpf::load(&[])?;
/// use aya::maps::xdp::DevMapHash;
///
/// let mut devmap = DevMapHash::try_from(bpf.map_mut("IFACES").unwrap())?;
/// let flags = 0;
/// let ifindex = 32u32;
/// devmap.insert(ifindex, ifindex, None::<i32>, flags);
///
/// # Ok::<(), aya::BpfError>(())
/// ```
#[doc(alias = "BPF_MAP_TYPE_DEVMAP_HASH")]
pub struct DevMapHash<T> {
    inner: T,
}

impl<T: AsRef<MapData>> DevMapHash<T> {
    pub(crate) fn new(map: T) -> Result<DevMapHash<T>, MapError> {
        let data = map.as_ref();
        check_kv_size::<u32, bpf_devmap_val>(data)?;

        let _fd = data.fd_or_err()?;

        Ok(DevMapHash { inner: map })
    }

    /// Returns the value stored at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::OutOfBounds`] if `index` is out of bounds, [`MapError::SyscallError`]
    /// if `bpf_map_lookup_elem` fails.
    pub fn get(&self, index: u32, flags: u64) -> Result<DevMapValue, MapError> {
        let fd = self.inner.as_ref().fd_or_err()?;
        let value = bpf_map_lookup_elem(fd, &index, flags).map_err(|(_, io_error)| {
            MapError::SyscallError {
                call: "bpf_map_lookup_elem".to_owned(),
                io_error,
            }
        })?;
        let value: bpf_devmap_val = value.ok_or(MapError::KeyNotFound)?;
        Ok(value.into())
    }

    /// An iterator over the elements of the devmap in arbitrary order. The iterator item type is
    /// `Result<(u32, u32), MapError>`.
    pub fn iter(&self) -> MapIter<'_, u32, DevMapValue, Self> {
        MapIter::new(self)
    }

    /// An iterator visiting all keys in arbitrary order. The iterator item type is
    /// `Result<u32, MapError>`.
    pub fn keys(&self) -> MapKeys<'_, u32> {
        MapKeys::new(self.inner.as_ref())
    }
}

impl<T: AsMut<MapData>> DevMapHash<T> {
    /// Inserts a value in the map.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::SyscallError`] if `bpf_map_update_elem` fails.
    pub fn insert(
        &mut self,
        index: u32,
        value: u32,
        program: Option<impl AsRawFd>,
        flags: u64,
    ) -> Result<(), MapError> {
        let value = bpf_devmap_val {
            ifindex: value,
            bpf_prog: bpf_devmap_val__bindgen_ty_1 {
                fd: program.map(|prog| prog.as_raw_fd()).unwrap_or_default(),
            },
        };
        hash_map::insert(self.inner.as_mut(), &index, &value, flags)
    }

    /// Remove a value from the map.
    ///
    /// # Errors
    ///
    /// Returns [`MapError::SyscallError`] if `bpf_map_delete_elem` fails.
    pub fn remove(&mut self, index: u32) -> Result<(), MapError> {
        hash_map::remove(self.inner.as_mut(), &index)
    }
}

impl<T: AsRef<MapData>> IterableMap<u32, DevMapValue> for DevMapHash<T> {
    fn map(&self) -> &MapData {
        self.inner.as_ref()
    }

    fn get(&self, key: &u32) -> Result<DevMapValue, MapError> {
        self.get(*key, 0)
    }
}
