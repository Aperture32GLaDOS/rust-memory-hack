use std::{ffi::c_void, fmt::Display, fs::File, io::Read, sync::{Arc, RwLock}};
use libc::{iovec, pid_t, process_vm_readv, process_vm_writev};
use rayon::prelude::*;

fn read_from_process<T: Default>(pid: pid_t, address: usize) -> Result<T, isize> {
    let mut output: T = T::default();
    let local_binding = iovec {
        iov_base: (&mut output as *mut _) as *mut c_void,
        iov_len: std::mem::size_of::<T>()
    };
    let remote_binding = iovec {
        iov_base: address as *mut c_void,
        iov_len: std::mem::size_of::<T>()
    };
    let nread = unsafe {
        process_vm_readv(pid, &local_binding as *const iovec, 1, &remote_binding as *const iovec, 1, 0)
    };
    if nread < 0 {
        return Err(nread);
    }
    Ok(output)
}

fn read_bytes_from_process(pid: pid_t, bytes: usize, address: usize) -> Result<Vec<u8>, isize> {
    let mut output: Vec<u8> = Vec::with_capacity(bytes);
    output.resize(bytes, 0);
    let local_binding: iovec = iovec {
        iov_base: output.as_mut_ptr() as *mut c_void,
        iov_len: bytes
    };
    let remote_binding: iovec = iovec {
        iov_base: address as *mut c_void,
        iov_len: bytes
    };
    let nread = unsafe {
        process_vm_readv(pid, &local_binding as *const iovec, 1, &remote_binding as *const iovec, 1, 0)
    };
    if nread < 0 {
        return Err(nread);
    }
    Ok(output)
}

fn write_to_process<T>(pid: pid_t, address: usize, to_write: &mut T) -> Result<(), isize> {
    let local_binding = iovec {
        iov_base: (to_write as *mut _) as *mut c_void,
        iov_len: std::mem::size_of::<T>()
    };
    let remote_binding = iovec {
        iov_base: address as *mut c_void,
        iov_len: std::mem::size_of::<T>()
    };
    let nwritten = unsafe {
        process_vm_writev(pid, &local_binding as *const iovec, 1, &remote_binding as *const iovec, 1, 0)
    };
    if nwritten < 0 {
        return Err(nwritten);
    }
    Ok(())
}

fn find_value<T: Default + PartialEq + Send + Sync>(pid: pid_t, value: T) -> Option<Vec<usize>> {
    let mut mem_maps_file = File::open(format!("/proc/{}/maps", pid)).ok()?;
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    let mut mem_maps: String = String::new();
    mem_maps_file.read_to_string(&mut mem_maps).ok()?;
    for line in mem_maps.lines() {
        let label = line.split_whitespace().last()?;
        let flags: _;
        {
            let mut iter = line.split_whitespace();
            iter.next()?;
            flags = iter.next()?;
        }
        if flags.contains('r') {
            let range = line.split_whitespace().next()?.split_once('-')?;
            let lower = usize::from_str_radix(range.0, 16).ok()?;
            let higher = usize::from_str_radix(range.1, 16).ok()?;
            ranges.push((lower, higher));
        }
    }
    let found: Arc<RwLock<Vec<usize>>> = Arc::new(RwLock::new(Vec::new()));
    ranges.par_iter().for_each(|x| {
        let base_address = x.0;
        let num_bytes = x.1 - x.0;
        // Copy the entire memory region, and then iterate over it
        let data: Result<Vec<u8>, isize> = read_bytes_from_process(pid, num_bytes, base_address);
        if data.is_err() {

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
    Some(Arc::into_inner(found).unwrap().into_inner().unwrap())
}

fn reduce_found_values<T: Default + PartialEq + Send + Sync>(pid: pid_t, found_values: &mut Vec<usize>, value: T) -> Option<()> {
    let desired_value = Ok(value);
    let to_remove: Arc<RwLock<Vec<usize>>> = Arc::new(RwLock::new(Vec::with_capacity(found_values.len())));
    found_values.par_iter().enumerate().for_each(|(index, address)| {
        if read_from_process(pid, *address) != desired_value {
            to_remove.write().unwrap().push(index);
        }
    });
    to_remove.write().unwrap().par_sort();
    for i in to_remove.read().unwrap().iter().rev() {
        found_values.remove(*i);
    }
    Some(())
}

fn display_found_values<T: Default + Display>(pid: pid_t, found_values: &Vec<usize>) {
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

fn lock_value<T: Send + Sync + 'static>(mut value: T, address: usize, pid: pid_t) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let local_binding = iovec {
            iov_base: (&mut value as *mut _) as *mut c_void,
            iov_len: std::mem::size_of::<T>()
        };
        let remote_binding = iovec {
            iov_base: address as *mut c_void,
            iov_len: std::mem::size_of::<T>()
        };
        loop {
            unsafe {
                process_vm_writev(pid, &local_binding as *const iovec, 1, &remote_binding as *const iovec, 1, 0);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<String>>();
    let pid = args[1].parse::<i32>()?;
    let mut buffer: String = String::new();
    let stdin = std::io::stdin();
    // Attach to the PID
    stdin.read_line(&mut buffer)?;
    let mut addresses: Vec<usize>;
    addresses = find_value(pid, buffer.trim().parse::<u8>().unwrap()).unwrap();
    let mut locks: Vec<std::thread::JoinHandle<()>> = Vec::new();
    loop {
        display_found_values::<u8>(pid, &addresses);
        buffer.clear();
        stdin.read_line(&mut buffer)?;
        if buffer.contains("stop") {
            break;
        }
        else if buffer.contains("write") {
            let mut new_value: u8 = buffer.split_whitespace().last().unwrap().trim().parse().unwrap();
            for address in &addresses {
                write_to_process(pid, *address, &mut new_value);
            }
        }
        else if buffer.contains("lock") {
            for _ in 0..locks.len() {
                locks.pop().unwrap().join().unwrap();
            }
            let mut new_value: u8 = buffer.split_whitespace().last().unwrap().trim().parse().unwrap();
            for address in &addresses {
                locks.push(lock_value(new_value, *address, pid));
            }
        }
        else {
            reduce_found_values(pid, &mut addresses, buffer.trim().parse::<u8>().unwrap());
        }
    }
    Ok(())
}
