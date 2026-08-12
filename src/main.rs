#![allow(dead_code)]
use std::{cmp::Reverse, collections::{BTreeSet, HashMap}, fs::File, io::{IoSlice, IoSliceMut, Read}, sync::{Arc, RwLock, atomic::AtomicBool}};
use nix::{sys::{uio::{process_vm_readv, RemoteIoVec, process_vm_writev}, ptrace::{seize, interrupt, cont, Options}}, unistd::Pid, };
use rayon::prelude::*;

#[derive(Clone)]
struct SendSyncRawPointer<T>(*mut T);

unsafe impl<T> Send for SendSyncRawPointer<T> {}
unsafe impl<T> Sync for SendSyncRawPointer<T> {}

struct MemoryInformation {
    pid: Pid,
    // TODO: store more information (i.e. the flags, label, etc.)
    memory_ranges: Vec<(usize, usize)>,
    cache_offsets: Vec<usize>,
    range_caches: Vec<u8>,
    locks: HashMap<usize, Arc<AtomicBool>>
}

impl MemoryInformation {
    fn from_pid(pid: Pid) -> Result<Self, Box<dyn std::error::Error>> {
        let mut information = Self{ pid, memory_ranges: Vec::new(), cache_offsets: Vec::new(), range_caches: Vec::new(), locks: HashMap::new() };
        information.update_memory_ranges()?;
        seize(pid, Options::empty())?;
        Ok(information)
    }

    fn update_cache(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.update_memory_ranges()?;
        self.cache_offsets.reserve(self.memory_ranges.len());
        let mut total_memory_length: usize = 0;
        for range in self.memory_ranges.iter() {
            let range_length = range.1 - range.0;
            self.cache_offsets.push(total_memory_length);
            total_memory_length += range_length;
        }
        self.range_caches.reserve(total_memory_length);
        // Some hacky pointer stuff
        unsafe {
            self.range_caches.set_len(total_memory_length);
        }
        let range_cache_ptr = SendSyncRawPointer(self.range_caches.as_mut_ptr());
        self.memory_ranges.par_iter().zip(self.cache_offsets.par_iter()).for_each(|(x, cache_offset)| {
            let range_length = x.1 - x.0;
            let range_bytes = self.read_bytes_from_process(range_length, x.0);
            let cache_ptr = &range_cache_ptr;
            let cache_slice;
            unsafe {
                let cache_slice_ptr = cache_ptr.0.offset(*cache_offset as isize);
                cache_slice = std::slice::from_raw_parts_mut(cache_slice_ptr, range_length);
            };
            match range_bytes {
                Ok(x) => {
                    cache_slice.par_iter_mut().zip(x.par_iter()).for_each(|x| *x.0 = *x.1);
                }
                Err(_) => {}
            }
        });
        Ok(())
    }

    fn pause(&self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(interrupt(self.pid)?)
    }

    fn resume(&self) -> Result<(), Box<dyn std::error::Error>> {
        Ok(cont(self.pid, None)?)
    }

    fn update_memory_ranges(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut mem_maps_file = File::open(format!("/proc/{}/maps", self.pid))?;
        self.memory_ranges.clear();
        let mut mem_maps: String = String::new();
        mem_maps_file.read_to_string(&mut mem_maps)?;
        const MEMORY_EMPTY_ERR: &'static str = "Expected no line in memory map to be empty";
        const MEMORY_RANGE_ERR: &'static str = "Expected each memory region to have address ranges";
        for line in mem_maps.lines() {
            let label: _;
            let flags: _;
            let (lower, higher);
            {
                let mut iter = line.split_whitespace();
                let range = iter.next().ok_or(MEMORY_EMPTY_ERR)?.split_once('-').ok_or(MEMORY_RANGE_ERR)?;
                lower = usize::from_str_radix(range.0, 16)?;
                higher = usize::from_str_radix(range.1, 16)?;
                flags = iter.next().ok_or::<&str>("Expected each line in memory map to contain memory flags".into())?;
                label = iter.last().ok_or(MEMORY_EMPTY_ERR)?;
            }
            if flags.contains('r') {
                self.memory_ranges.push((lower, higher));
            }
        }
        Ok(())
    }

    fn find_value<T: PartialEq + Send + Sync>(&self, value: T) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
        let found = self.memory_ranges.par_iter().filter_map(|x| {
            let mut base_address = x.0;
            // Align the base address
            base_address += std::mem::align_of::<T>() - (base_address % std::mem::align_of::<T>());
            let num_bytes = x.1 - x.0;
            // Copy the entire memory region, and then iterate over it
            let data: Result<Vec<u8>, Box<dyn std::error::Error>> = self.read_bytes_from_process(num_bytes, base_address);
            if data.is_err() {
                // TODO: error report maybe?
                return None;
            }
            else {
                Some(data.unwrap().par_iter().enumerate().step_by(std::mem::align_of::<T>()).filter_map(|(offset, x)| {
                    let address = base_address + offset;
                    // If we cannot read the required number of bytes, then do not attempt to
                    if offset + std::mem::size_of_val(&value) >= num_bytes {
                        return None;
                    }
                    else {
                        let pointer = (x as *const u8) as *const T;
                        unsafe {
                            let data = &*pointer;
                            if *data == value {
                                return Some(address);
                            }
                            else {
                                return None;
                            }
                        }
                    }
                }).collect::<Vec<usize>>())
            }
        }).flatten().collect::<Vec<usize>>();
        Ok(found)
    }

    fn find_value_by_predicate<T: Sized, K: Fn(&T) -> bool + Sync>(&self, predicate: K) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
        let found = self.memory_ranges.par_iter().filter_map(|x| {
            let mut base_address = x.0;
            base_address += std::mem::align_of::<T>() - (base_address % std::mem::align_of::<T>());
            let num_bytes = x.1 - x.0;
            // Copy the entire memory region, and then iterate over it
            let data: Result<Vec<u8>, Box<dyn std::error::Error>> = self.read_bytes_from_process(num_bytes, base_address);
            if data.is_err() {
                // TODO: error report maybe?
                return None;
            }
            else {
                Some(data.unwrap().par_iter().enumerate().step_by(std::mem::align_of::<T>()).filter_map(|(offset, x)| {
                    let address = base_address + offset;
                    // If we cannot read the required number of bytes, then do not attempt to
                    if offset + std::mem::size_of::<T>() >= num_bytes {
                        return None;
                    }
                    else {
                        let pointer = (x as *const u8) as *const T;
                        unsafe {
                            let data = &*pointer;
                            if predicate(data) {
                                return Some(address);
                            }
                            else {
                                return None;
                            }
                        }
                    }
                }).collect::<Vec<usize>>())
            }
        }).flatten().collect();
        Ok(found)
    }

    // This method uses the cache as it is used in the pointer chain finding
    fn execute_func_on_memory<T: Sized, K: Fn(usize, &T) + Sync>(&self, predicate: K) -> Result<(), Box<dyn std::error::Error>> {
        let cache_ptr = SendSyncRawPointer(self.range_caches.as_ptr() as *mut u8);
        self.cache_offsets.par_iter().zip(self.memory_ranges.par_iter()).for_each(|(cache_offset, range)| {
            let data: &[u8];
            let num_bytes = range.1 - range.0;
            let ref_cache_ptr = &cache_ptr;
            let base_address = range.0;
            let align_offset = std::mem::align_of::<T>() - base_address % std::mem::align_of::<T>();
            unsafe {
                let cache_slice_ptr = ref_cache_ptr.0.byte_offset(*cache_offset as isize + (align_offset as isize));
                data = std::slice::from_raw_parts(cache_slice_ptr as *const u8, num_bytes - align_offset);
            }
            data.par_iter().enumerate().step_by(std::mem::align_of::<T>()).for_each(|(offset, x)| {
                let address = range.0 + offset + align_offset;
                // If we cannot read the required number of bytes, then do not attempt to
                if offset + std::mem::size_of::<T>() >= num_bytes {}
                else {
                    let pointer = (x as *const u8) as *const T;
                    unsafe {
                        let data = &*pointer;
                        predicate(address, data);
                    }
                }
            });
        });
        Ok(())
    }

    fn collect_values<T: Send + Sync>(&self) -> Vec<(usize, T)> {
        let cache_ptr = SendSyncRawPointer(self.range_caches.as_ptr() as *mut u8);
        self.cache_offsets.par_iter().zip(self.memory_ranges.par_iter()).map(|(cache_offset, range)| {
            let cache_ptr_ref = &cache_ptr;
            let ptr = cache_ptr_ref.0;
            let data: &[u8];
            let num_bytes = range.1 - range.0;
            let base_address = range.0;
            let align_offset = (std::mem::align_of::<T>() - base_address % std::mem::align_of::<T>()) % std::mem::align_of::<T>();
            unsafe {
                let cache_slice_ptr = ptr.byte_offset(*cache_offset as isize + (align_offset as isize));
                data = std::slice::from_raw_parts(cache_slice_ptr, num_bytes - align_offset);
            }
            data.par_iter().enumerate().step_by(std::mem::align_of::<T>()).filter_map(|(offset, x)| {
                let address = base_address + offset + align_offset;
                if offset + std::mem::size_of::<T>() >= num_bytes {
                    return None;
                }
                else {
                    let pointer = (x as *const u8) as *const T;
                    unsafe {
                        let data = std::ptr::read_unaligned(pointer);
                        return Some((address, data));
                    }
                }
            }).collect::<Vec<(usize, T)>>()
        }).flatten().collect()
    }

    fn collect_values_from_memory_range<T: Send + Sync>(&self, memory_range_index: usize) -> Vec<(usize, T)> {
        let cache_offset = self.cache_offsets[memory_range_index];
        let range = self.memory_ranges[memory_range_index];
        let ptr = self.range_caches.as_ptr();
        let data: &[u8];
        let num_bytes = range.1 - range.0;
        let base_address = range.0;
        let align_offset = (std::mem::align_of::<T>() - base_address % std::mem::align_of::<T>()) % std::mem::align_of::<T>();
        unsafe {
            let cache_slice_ptr = ptr.byte_offset(cache_offset as isize + (align_offset as isize));
            data = std::slice::from_raw_parts(cache_slice_ptr, num_bytes - align_offset);
        }
        data.par_iter().enumerate().step_by(std::mem::align_of::<T>()).filter_map(|(offset, x)| {
            let address = base_address + offset + align_offset;
            if offset + std::mem::size_of::<T>() >= num_bytes {
                return None;
            }
            else {
                let pointer = (x as *const u8) as *const T;
                unsafe {
                    let data = std::ptr::read_unaligned(pointer);
                    return Some((address, data));
                }
            }
        }).collect::<Vec<(usize, T)>>()
    }

    fn read_from_process<T: Default + Sized>(&self, address: usize) -> Result<T, Box<dyn std::error::Error>> {
        let mut output: T = T::default();
        let buffer: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut((&mut output as *mut T) as *mut u8, std::mem::size_of::<T>())
        };
        let local_binding = IoSliceMut::new(buffer);
        let remote_binding = RemoteIoVec{ base: address, len: std::mem::size_of::<T>() };
        process_vm_readv(self.pid, &mut [local_binding], &[remote_binding])?;
        Ok(output)
    }

    fn read_from_process_cached<T: Default + Sized>(&self, address: usize) -> Result<&T, Box<dyn std::error::Error>> {
        for (range, cache_offset) in self.memory_ranges.iter().zip(self.cache_offsets.iter()) {
            if (range.0..range.1).contains(&address) {
                let mut pointer = self.range_caches.as_ptr() as *const T;
                unsafe {
                    pointer = pointer.byte_offset(*cache_offset as isize);
                    pointer = pointer.byte_offset((address - range.0) as isize);
                    return Ok(&*pointer);
                }
            }
        }
        Err("Unable to find address in cache".into())
    }

    fn read_bytes_from_process(&self, bytes: usize, address: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut output: Vec<u8> = Vec::with_capacity(bytes);
        output.resize(bytes, 0);
        let local_binding = IoSliceMut::new(&mut output);
        let remote_binding = RemoteIoVec{ base: address, len: bytes };
        process_vm_readv(self.pid, &mut [local_binding], &[remote_binding])?;
        Ok(output)
    }

    fn write_to_process<T>(&self, address: usize, to_write: &T) -> Result<(), Box<dyn std::error::Error>> {
        let local_binding = IoSlice::new(unsafe {
            std::slice::from_raw_parts((to_write as *const T as *mut T) as *mut u8, std::mem::size_of_val(to_write))
        });
        let remote_binding = RemoteIoVec{ base: address, len: std::mem::size_of_val(to_write) };
        process_vm_writev(self.pid, &[local_binding], &[remote_binding])?;
        Ok(())
    }

    // Shouldn't really use the cache, since this method will be called while the program is
    // changing
    fn reduce_found_values<T: Default + PartialEq + Send + Sync>(&self, found_values: &mut Vec<usize>, value: T) -> Result<(), Box<dyn std::error::Error>> {
        let mut to_keep = found_values.par_iter().filter_map(|address| {
            let read_value: Result<T, _> = self.read_from_process(*address);
            match read_value {
                Ok(x) => {
                    if x == value {
                        return Some(*address);
                    }
                    else {
                        return None;
                    }
                }
                Err(_) => {
                    return None;
                }
            }
        }).collect::<Vec<usize>>();
        std::mem::swap(found_values, &mut to_keep);
        Ok(())
    }

    fn reduce_found_values_by_predicate<T: Default, K: Fn(&T) -> bool + Sync>(&self, found_values: &mut Vec<usize>, predicate: K) -> Result<(), Box<dyn std::error::Error>> {
        let mut to_keep = found_values.par_iter().filter_map(|address| {
            let read_value: Result<T, _> = self.read_from_process(*address);
            match read_value {
                Ok(x) => {
                    if predicate(&x) {
                        return Some(*address);
                    }
                    else {
                        return None;
                    }
                }
                Err(_) => {
                    return None;
                }
            }
        }).collect::<Vec<usize>>();
        std::mem::swap(found_values, &mut to_keep);
        Ok(())
    }

    fn lock_value<T: Send + Sync + 'static>(&mut self, value: T, address: usize) {
        let atomic_bool = Arc::new(AtomicBool::new(true));
        let threads_bool = atomic_bool.clone();
        let pid: Pid = self.pid;
        std::thread::spawn(move || {
            let local_binding = IoSlice::new(unsafe {
                std::slice::from_raw_parts((&value as *const T) as *const u8, std::mem::size_of_val(&value))
            });
            let remote_binding = RemoteIoVec{ base: address, len: std::mem::size_of_val(&value) };
            while threads_bool.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = process_vm_writev(pid, &[local_binding], &[remote_binding]);
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        });
        self.locks.insert(address, atomic_bool);
    }

    fn unlock_value(&mut self, address: usize) {
        let atomic_bool = self.locks.get(&address);
        match atomic_bool {
            Some(x) => {
                x.store(false, std::sync::atomic::Ordering::Relaxed);
                self.locks.remove(&address);
            }
            None => {}
        }
    }
}

#[derive(Eq, Hash, PartialEq, Clone, Debug)]
struct IncompletePointerChain {
    base_address: usize,
    offset: isize,
    // To avoid expensive vectors of offsets being cloned
    next_chain: Option<Arc<IncompletePointerChain>>
}

impl IncompletePointerChain {
    fn from_address(address: usize) -> Self {
        Self { base_address: address, offset: 0, next_chain: None }
    }

    fn get_pointed_address(&self, memory_information: &MemoryInformation) -> Result<usize, Box<dyn std::error::Error>> {
        let mut address = self.base_address;
        // Dereference the base location
        address = *memory_information.read_from_process_cached(address)?;
        // And add the offset
        address = (address as isize + self.offset) as usize;
        let mut next_chain_optional = &self.next_chain;
        while let Some(next_chain) = next_chain_optional {
            next_chain_optional = &next_chain.next_chain;
            // Do not dereference at the last offset
            if next_chain_optional.is_some() {
                address = *memory_information.read_from_process_cached(address)?;
            }
            // Offset
            address = (address as isize + next_chain.offset) as usize;
        }

        Ok(address)
    }

    // TODO: this method is very fast, but too permissive with its possible memory chains. At depth
    // 7, it will happily eat all 64 GB of my RAM on my machine - maybe try restricting early
    // pointer chains to their own memory region?
    fn get_pointer_chains(memory_information: &mut MemoryInformation, final_address: usize, maximum_offset: usize, depth: usize) -> Result<Vec<IncompletePointerChain>, Box<dyn std::error::Error>> {
        let mut current_chains = Arc::new(RwLock::new(vec![Arc::new(Self::from_address(final_address))]));
        let mut next_chains: Arc<RwLock<Vec<Arc<IncompletePointerChain>>>> = Arc::new(RwLock::new(Vec::new()));
        // Vector of tuples of (my_address, what_i_point_to)
        // We can sort this vector by what_i_point_to to efficiently extract slices of addresses which
        // point to values within a certain range
        let mut all_possible_pointer_values: Vec<(usize, usize)> = memory_information.collect_values();
        all_possible_pointer_values.par_sort_unstable_by_key(|(_address, pointed_to)| *pointed_to);
        let all_possible_pointer_values = Arc::new(all_possible_pointer_values);
        for _ in 0..depth {
            current_chains.read().unwrap().par_iter().for_each(|x| {
                // We expect the pointer to point to a slightly lower address
                let lower_bound = x.base_address - maximum_offset;
                let upper_bound = x.base_address;
                let lower_bound_index = all_possible_pointer_values.partition_point(|(_address, pointed_to)| *pointed_to < lower_bound);
                let mut upper_bound_index = all_possible_pointer_values.partition_point(|(_address, pointed_to)| *pointed_to < upper_bound);
                while all_possible_pointer_values[upper_bound_index].1 > upper_bound {
                    upper_bound_index -= 1;
                }
                if lower_bound_index > upper_bound_index {
                    return;
                }
                else if lower_bound_index == upper_bound_index {
                    let pointer = all_possible_pointer_values[upper_bound_index];
                    next_chains.write().unwrap().push(Arc::new(IncompletePointerChain {
                        base_address: pointer.0,
                        offset: (x.base_address as isize) - (pointer.1) as isize,
                        next_chain: Some(x.clone())
                    }));
                }
                let possible_pointer_slice = &all_possible_pointer_values[lower_bound_index..upper_bound_index];
                // Each thread temporarily owns a write-lock to write all its new pointer chains to
                // the next_chains Vec through one .extend call
                // (bit slower than having each thread build its own local and then .extend-ing the
                // next_chains Vec but far nicer on memory usage)
                next_chains.write().unwrap().extend(possible_pointer_slice.iter().map(|pointer| {
                    let new_chain = IncompletePointerChain {
                        base_address: pointer.0,
                        offset: (x.base_address as isize) - (pointer.1) as isize,
                        next_chain: Some(x.clone())
                    };
                    Arc::new(new_chain)
                }));
            });
            std::mem::swap(&mut current_chains, &mut next_chains);
            next_chains.write().unwrap().clear();
        }
        // Guaranteed that we can call into_inner on the Vec<Arc<_>> values since they would only be
        // shared by the next iteration (which, by definition, hasn't been computed yet)
        Ok(Arc::into_inner(current_chains).unwrap().into_inner().unwrap().into_iter().map(|x| Arc::into_inner(x).unwrap()).collect())
    }

    // Takes ownership of the existing pointer chains to avoid .clone-ing potentially lots of IncompletePointerChain
    fn prune_pointer_chains(memory_information: &mut MemoryInformation, final_address: usize, existing_chains: Vec<IncompletePointerChain>) -> Result<Vec<IncompletePointerChain>, Box<dyn std::error::Error>>{
        let to_keep = existing_chains.into_par_iter().filter_map(|x| {
            match x.get_pointed_address(memory_information) {
                Ok(pointed) => {
                    if pointed == final_address {
                        Some(x)
                    }
                    else {
                        None
                    }
                }
                _ => {
                    None
                }
            }
        }).collect::<Vec<IncompletePointerChain>>();
        Ok(to_keep)
    }
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<String>>();
    let pid = Pid::from_raw(args[1].parse::<i32>()?);
    let mut memory_information = MemoryInformation::from_pid(pid)?;
    let mut buffer: String = String::new();
    let stdin = std::io::stdin();
    stdin.read_line(&mut buffer)?;
    let address = usize::from_str_radix(buffer.trim(), 16)?;
    buffer.clear();
    memory_information.pause()?;
    memory_information.update_cache()?;
    memory_information.resume()?;
    let pointer_chains = IncompletePointerChain::get_pointer_chains(&mut memory_information, address, 0xfff, 6)?;
    println!("{} possible pointer chains", pointer_chains.len());
    stdin.read_line(&mut buffer)?;
    memory_information.pause()?;
    memory_information.update_cache()?;
    memory_information.resume()?;
    let pointer_chains = IncompletePointerChain::prune_pointer_chains(&mut memory_information, address, pointer_chains)?;
    println!("After pruning: {} possible pointer chains", pointer_chains.len());
    // let mut possible_addresses: Vec<usize> = memory_information.find_value(buffer.trim().parse::<u8>()?)?;
    // loop {
    //     buffer.clear();
    //     stdin.read_line(&mut buffer)?;
    //     memory_information.pause()?;
    //     memory_information.update_memory_ranges()?;
    //     memory_information.reduce_found_values(&mut possible_addresses, buffer.trim().parse::<u8>()?)?;
    //     memory_information.resume()?;
    //     println!("{} possibilities", possible_addresses.len());
    //     if possible_addresses.len() < 10 {
    //         println!("{:x}", possible_addresses[0]);
    //     }
    // }
    Ok(())
}
