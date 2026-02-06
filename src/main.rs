use std::{collections::HashMap, ffi::c_void, fmt::Display, fs::File, io::{IoSlice, IoSliceMut, Read}, sync::{Arc, RwLock}, thread::JoinHandle};
use libc::{iovec, pid_t};
use nix::{errno::Errno, sys::uio::{process_vm_readv, RemoteIoVec, process_vm_writev}, unistd::Pid};
use rayon::prelude::*;

fn read_from_process<T: Default>(pid: Pid, address: usize) -> Result<T, Box<dyn std::error::Error>> {
    let mut output: T = T::default();
    let buffer: &mut [u8] = unsafe {
        std::slice::from_raw_parts_mut((&mut output as *mut T) as *mut u8, std::mem::size_of::<T>())
    };
    let local_binding = IoSliceMut::new(buffer);
    let remote_binding = RemoteIoVec{ base: address, len: std::mem::size_of::<T>() };
    process_vm_readv(pid, &mut [local_binding], &[remote_binding])?;
    Ok(output)
}

fn read_bytes_from_process(pid: Pid, bytes: usize, address: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut output: Vec<u8> = Vec::with_capacity(bytes);
    output.resize(bytes, 0);
    let local_binding = IoSliceMut::new(&mut output);
    let remote_binding = RemoteIoVec{ base: address, len: bytes };
    process_vm_readv(pid, &mut [local_binding], &[remote_binding])?;
    Ok(output)
}

fn write_to_process<T>(pid: Pid, address: usize, to_write: &mut T) -> Result<(), Box<dyn std::error::Error>> {
    let local_binding = IoSlice::new(unsafe {
        std::slice::from_raw_parts((to_write as *mut T) as *mut u8, std::mem::size_of::<T>())
    });
    let remote_binding = RemoteIoVec{ base: address, len: std::mem::size_of::<T>() };
    process_vm_writev(pid, &[local_binding], &[remote_binding])?;
    Ok(())
}

fn find_value<T: Default + PartialEq + Send + Sync>(pid: Pid, value: T) -> Result<Vec<usize>, Box<dyn std::error::Error>> {
    let mut mem_maps_file = File::open(format!("/proc/{}/maps", pid))?;
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut mem_maps: String = String::new();
    mem_maps_file.read_to_string(&mut mem_maps)?;
    const memory_empty_err: &'static str = "Expected no line in memory map to be empty";
    const memory_range_err: &'static str = "Expected each memory region to have address ranges";
    for line in mem_maps.lines() {
        let label = line.split_whitespace().last().ok_or(memory_empty_err)?;
        let flags: _;
        {
            let mut iter = line.split_whitespace();
            iter.next().ok_or(memory_empty_err)?;
            flags = iter.next().ok_or::<&str>("Expected each line in memory map to contain memory flags".into())?;
        }
        if flags.contains('r') {
            let range = line.split_whitespace().next().ok_or(memory_empty_err)?.split_once('-').ok_or(memory_range_err)?;
            let lower = usize::from_str_radix(range.0, 16)?;
            let higher = usize::from_str_radix(range.1, 16)?;
            ranges.push((lower, higher));
        }
    }
    let found: Arc<RwLock<Vec<usize>>> = Arc::new(RwLock::new(Vec::new()));
    ranges.par_iter().for_each(|x| {
        let base_address = x.0;
        let num_bytes = x.1 - x.0;
        // Copy the entire memory region, and then iterate over it
        let data: Result<Vec<u8>, Box<dyn std::error::Error>> = read_bytes_from_process(pid, num_bytes, base_address);
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

fn reduce_found_values<T: Default + PartialEq + Send + Sync>(pid: Pid, found_values: &mut Vec<usize>, value: T) -> Result<(), Box<dyn std::error::Error>> {
    let to_remove: Arc<RwLock<Vec<usize>>> = Arc::new(RwLock::new(Vec::with_capacity(found_values.len())));
    found_values.par_iter().enumerate().for_each(|(index, address)| {
        let read_value: Result<T, _> = read_from_process(pid, *address);
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

fn display_found_values<T: Default + Display>(pid: Pid, found_values: &Vec<usize>) {
    if found_values.len() > 10 {
        println!("Possible values: {}", found_values.len());
    }
    else {
        println!("Possible values: {}", found_values.len());
        for address in found_values {
            let value: T;
            value = read_from_process(pid, *address).unwrap();
            println!("Value: {} @ 0x{:x}", value, address);
        }
    }
}

fn lock_value<T: Send + Sync + 'static>(value: T, address: usize, pid: Pid, locks: &mut HashMap<usize, JoinHandle<()>>) {
    locks.insert(address, std::thread::spawn(move || {
        let local_binding = IoSlice::new(unsafe {
            std::slice::from_raw_parts((&value as *const T) as *const u8, std::mem::size_of::<T>())
        });
        let remote_binding = RemoteIoVec{ base: address, len: std::mem::size_of::<T>() };
        loop {
            process_vm_writev(pid, &[local_binding], &[remote_binding]);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }));
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<String>>();
    let pid = Pid::from_raw(args[1].parse::<i32>()?);
    let mut buffer: String = String::new();
    let stdin = std::io::stdin();
    stdin.read_line(&mut buffer)?;
    let mut locks: Vec<std::thread::JoinHandle<()>> = Vec::new();
    Ok(())
}
