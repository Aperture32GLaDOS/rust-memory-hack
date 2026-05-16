use std::{collections::HashMap, fs::File, io::{IoSlice, IoSliceMut, Read}, sync::{atomic::AtomicBool, Arc, RwLock}};
use nix::{sys::{uio::{process_vm_readv, RemoteIoVec, process_vm_writev}, ptrace::{seize, interrupt, cont, Options}}, unistd::Pid, };
use rayon::prelude::*;

struct MemoryInformation {
    pid: Pid,
    // TODO: store more information (i.e. the flags, label, etc.)
    memory_ranges: Vec<(usize, usize)>,
    locks: HashMap<usize, Arc<AtomicBool>>
}

impl MemoryInformation {
    fn from_pid(pid: Pid) -> Result<Self, Box<dyn std::error::Error>> {
        let mut information = Self{ pid, memory_ranges: Vec::new(), locks: HashMap::new() };
        information.update_memory_ranges()?;
        seize(pid, Options::empty())?;
        Ok(information)
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
            let label = line.split_whitespace().last().ok_or(MEMORY_EMPTY_ERR)?;
            let flags: _;
            {
                let mut iter = line.split_whitespace();
                iter.next().ok_or(MEMORY_EMPTY_ERR)?;
                flags = iter.next().ok_or::<&str>("Expected each line in memory map to contain memory flags".into())?;
            }
            if flags.contains('r') {
                let range = line.split_whitespace().next().ok_or(MEMORY_EMPTY_ERR)?.split_once('-').ok_or(MEMORY_RANGE_ERR)?;
                let lower = usize::from_str_radix(range.0, 16)?;
                let higher = usize::from_str_radix(range.1, 16)?;
                self.memory_ranges.push((lower, higher));
            }
        }
        Ok(())
    }

    fn find_value<T: PartialEq + Send + Sync>(&self, value: T) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
        let found: Arc<RwLock<Vec<usize>>> = Arc::new(RwLock::new(Vec::new()));
        self.memory_ranges.par_iter().for_each(|x| {
            let base_address = x.0;
            let num_bytes = x.1 - x.0;
            // Copy the entire memory region, and then iterate over it
            let data: Result<Vec<u8>, Box<dyn std::error::Error>> = self.read_bytes_from_process(num_bytes, base_address);
            if data.is_err() {
                // TODO: error report maybe?
            }
            else {
                data.unwrap().par_iter().enumerate().for_each(|(offset, x)| {
                    let address = base_address + offset;
                    // If we cannot read the required number of bytes, then do not attempt to
                    if offset + std::mem::size_of_val(&value) >= num_bytes {}
                    else {
                        let pointer = (x as *const u8) as *const T;
                        unsafe {
                            let data = &*pointer;
                            if *data == value {
                                found.write().unwrap().push(address);
                            }
                        }
                    }
                });
            }
        });
        Ok(Arc::into_inner(found).unwrap().into_inner().unwrap())
    }

    fn find_value_by_predicate<T: Sized, K: Fn(&T) -> bool + Sync>(&self, predicate: K) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
        let found: Arc<RwLock<Vec<usize>>> = Arc::new(RwLock::new(Vec::new()));
        self.memory_ranges.par_iter().for_each(|x| {
            let base_address = x.0;
            let num_bytes = x.1 - x.0;
            // Copy the entire memory region, and then iterate over it
            let data: Result<Vec<u8>, Box<dyn std::error::Error>> = self.read_bytes_from_process(num_bytes, base_address);
            if data.is_err() {
                // TODO: error report maybe?
            }
            else {
                data.unwrap().par_iter().enumerate().for_each(|(offset, x)| {
                    let address = base_address + offset;
                    // If we cannot read the required number of bytes, then do not attempt to
                    if offset + std::mem::size_of::<T>() >= num_bytes {}
                    else {
                        let pointer = (x as *const u8) as *const T;
                        unsafe {
                            let data = &*pointer;
                            if predicate(data) {
                                found.write().unwrap().push(address);
                            }
                        }
                    }
                });
            }
        });
        Ok(Arc::into_inner(found).unwrap().into_inner().unwrap())
    }

    fn find_and_map_value_by_predicate<T: Sized, Y: Send + Sync, K: Fn(usize, &T) -> (bool, Y) + Sync>(&self, predicate: K) -> Result<Vec<Y>, Box<dyn std::error::Error>> {
        let found: Arc<RwLock<Vec<Y>>> = Arc::new(RwLock::new(Vec::new()));
        self.memory_ranges.par_iter().for_each(|x| {
            let base_address = x.0;
            let num_bytes = x.1 - x.0;
            // Copy the entire memory region, and then iterate over it
            let data: Result<Vec<u8>, Box<dyn std::error::Error>> = self.read_bytes_from_process(num_bytes, base_address);
            if data.is_err() {
                // TODO: error report maybe?
            }
            else {
                data.unwrap().par_iter().enumerate().for_each(|(offset, x)| {
                    let address = base_address + offset;
                    // If we cannot read the required number of bytes, then do not attempt to
                    if offset + std::mem::size_of::<T>() >= num_bytes {}
                    else {
                        let pointer = (x as *const u8) as *const T;
                        unsafe {
                            let data = &*pointer;
                            let (has_found, mapped) = predicate(address, data);
                            if has_found {
                                found.write().unwrap().push(mapped);
                            }
                        }
                    }
                });
            }
        });
        Ok(Arc::into_inner(found).unwrap().into_inner().unwrap())
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

    fn read_bytes_from_process(&self, bytes: usize, address: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut output: Vec<u8> = Vec::with_capacity(bytes);
        output.resize(bytes, 0);
        let local_binding = IoSliceMut::new(&mut output);
        let remote_binding = RemoteIoVec{ base: address, len: bytes };
        process_vm_readv(self.pid, &mut [local_binding], &[remote_binding])?;
        Ok(output)
    }

    fn write_to_process<T>(&self, address: usize, to_write: &mut T) -> Result<(), Box<dyn std::error::Error>> {
        let local_binding = IoSlice::new(unsafe {
            std::slice::from_raw_parts((to_write as *mut T) as *mut u8, std::mem::size_of_val(to_write))
        });
        let remote_binding = RemoteIoVec{ base: address, len: std::mem::size_of_val(to_write) };
        process_vm_writev(self.pid, &[local_binding], &[remote_binding])?;
        Ok(())
    }

    fn reduce_found_values<T: Default + PartialEq + Send + Sync>(&self, found_values: &mut Vec<usize>, value: T) -> Result<(), Box<dyn std::error::Error>> {
        let to_remove: Arc<RwLock<Vec<usize>>> = Arc::new(RwLock::new(Vec::with_capacity(found_values.len())));
        found_values.par_iter().enumerate().for_each(|(index, address)| {
            let read_value: Result<T, _> = self.read_from_process(*address);
            match read_value {
                Ok(x) => {
                    if x != value {
                        to_remove.write().unwrap().push(index);
                    }
                }
                Err(_) => {}
            }
        });
        to_remove.write().unwrap().par_sort();
        for i in to_remove.read().unwrap().iter().rev() {
            found_values.remove(*i);
        }
        Ok(())
    }

    fn reduce_found_values_by_predicate<T: Default, K: Fn(&T) -> bool + Sync>(&self, found_values: &mut Vec<usize>, predicate: K) -> Result<(), Box<dyn std::error::Error>> {
        let to_remove: Arc<RwLock<Vec<usize>>> = Arc::new(RwLock::new(Vec::with_capacity(found_values.len())));
        found_values.par_iter().enumerate().for_each(|(index, address)| {
            let read_value: Result<T, _> = self.read_from_process(*address);
            match read_value {
                Ok(x) => {
                    if !predicate(&x) {
                        to_remove.write().unwrap().push(index);
                    }
                }
                Err(_) => {}
            }
        });
        to_remove.write().unwrap().par_sort();
        for i in to_remove.read().unwrap().iter().rev() {
            found_values.remove(*i);
        }
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


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<String>>();
    let pid = Pid::from_raw(args[1].parse::<i32>()?);
    let mut memory_information = MemoryInformation::from_pid(pid)?;
    let mut buffer: String = String::new();
    let stdin = std::io::stdin();
    stdin.read_line(&mut buffer)?;
    Ok(())
}
