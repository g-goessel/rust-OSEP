use core::slice;
use std::{env, ptr};

use windows_sys::core::PCWSTR;
use windows_sys::core::PWSTR;
use windows_sys::core::PSTR;
use windows_sys::Win32::Foundation::{GetLastError, HANDLE};
use windows_sys::Win32::Security::GetTokenInformation;
use windows_sys::Win32::Security::TokenUser;
use windows_sys::Win32::Security::TOKEN_ADJUST_SESSIONID;
use windows_sys::Win32::Security::TOKEN_ALL_ACCESS;
use windows_sys::Win32::Storage::FileSystem::ReadFile;
use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
use windows_sys::Win32::System::Pipes::CreateNamedPipeW;
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::GetCurrentThread;
use windows_sys::Win32::System::Threading::OpenThreadToken;
use windows_sys::Win32::Security::TOKEN_USER;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidA;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Invalid number of args");
        println!("Impersonate_with_pipes.exe pipename");
        return;
    }
    //    dbg!(args);
    let pipe_name = &args[1];
    println!("Creating pipe named: {}", pipe_name);
    let mut v: Vec<u16> = pipe_name.encode_utf16().collect();
    v.push(0);
    let lpname: PCWSTR = v.as_ptr();
    let handle: HANDLE =
        unsafe { CreateNamedPipeW(lpname, 3, 0, 10, 0x1000, 0x1000, 0, ptr::null()) };
    if handle <= 0 {
        println!("Pipe creation failed");
        println!("Error: {}", unsafe { GetLastError() });
        return;
    }
    println!(
        "Pipe {} has been created. Now waiting for conection.",
        pipe_name
    );

    if unsafe { ConnectNamedPipe(handle, ptr::null_mut()) } == 0 {
        println!("Couldn't attach to pipe");
        println!("Error: {}", unsafe { GetLastError() });
        return;
    }
    println!("Connection to pipe established.");

    // We need to read data before impersonating
    const DATA_BUFFER_SIZE: u32 = 1024;
    let mut data_read: u32 = 0;
    let mut data_buffer: Vec<u8> = Vec::with_capacity(DATA_BUFFER_SIZE as _);
    let read_data = unsafe {
        ReadFile(
            handle,
            data_buffer.as_mut_ptr() as _,
            DATA_BUFFER_SIZE,
            &mut data_read,
            std::ptr::null_mut(),
        )
    };
    if read_data == 0 {
        println!("Couldn't read pipe data");
        println!("Error: {}", unsafe { GetLastError() });
        return;
    }
    println!("Bytes read from pipe: {}", data_read);

    if unsafe { ImpersonateNamedPipeClient(handle) } == 0 {
        println!("Couldn't impersonate pipe client");
        println!("Error: {}", unsafe { GetLastError() });
        return;
    }
    println!("Pipe client impersonated");

    let mut h_token: HANDLE = 0;
    let curr_thread: HANDLE = unsafe { GetCurrentThread() };
    if unsafe {
        OpenThreadToken(
            curr_thread,
            TOKEN_ALL_ACCESS | TOKEN_ADJUST_SESSIONID,
            0,
            &mut h_token,
        )
    } == 0
    {
        println!("Failed to get Thread info");
        println!("Error: {}", unsafe { GetLastError() });
        return;
    }
    println!("Found handle: {}", h_token);

    let mut TokenInfLength: u32 = 0;
    unsafe { GetTokenInformation(h_token, TokenUser, ptr::null_mut(), 0, &mut TokenInfLength) };
    if TokenInfLength == 0 {
        println!("Couldn't determine TokenInformation length");
        println!("Error: {}", unsafe { GetLastError() });
        return;
    };
    println!("TokenInformation len: {}", TokenInfLength);

    let mut token_info_buffer = Vec::<u8>::new();
    token_info_buffer.resize(TokenInfLength as usize, 0);
    if unsafe {
        GetTokenInformation(
            h_token,
            TokenUser,
            token_info_buffer.as_mut_ptr() as *mut core::ffi::c_void,
            TokenInfLength,
            &mut TokenInfLength,
        )
    } == 0
    {
        println!("Couldn't read TokenInformation data");
        println!("Error: {}", unsafe { GetLastError() });
        return;
    };
    let token_info = token_info_buffer.as_ptr() as *const TOKEN_USER;
    let mut stringsid: PSTR  = ptr::null_mut();
    if unsafe{ConvertSidToStringSidA((*token_info).User.Sid, &mut stringsid)} == 0{
        println!("Couldn't ConvertSidToStringSidW");
        println!("Error: {}", unsafe { GetLastError() });
        return;
    };
    let len = unsafe{(0..).take_while(|&i| *stringsid.offset(i) != 0).count()};
    dbg!(len);
    let sid_str_slice = unsafe{core::slice::from_raw_parts(stringsid, len)};
    let sid_str = String::from_utf8_lossy(sid_str_slice);
    println!("Impersonated User SID: {}", sid_str);
//    let buffer = unsafe { slice::from_raw_parts((*token_info).User.Sid, stringsid as usize - 1) };
//    dbg!(buffer);
//    let sid = unsafe{String::from_utf16_lossy(*stringsid)};
//    println!("{}", *stringsid);
//    dbg!((*token_info).User);
}
