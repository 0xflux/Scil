use std::iter::once;

use shared::DRIVER_NAME;
use windows::{
    Win32::{
        Foundation::{GENERIC_ALL, HANDLE},
        Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_SYSTEM, FILE_SHARE_NONE, OPEN_EXISTING},
        System::Threading::Sleep,
    },
    core::PCWSTR,
};

use crate::ioctl::drain_driver_messages;

mod ioctl;

fn main() {
    println!("Starting SCIL engine..");
    run_engine();
}

fn run_engine() {
    let device = get_driver_handle_or_panic();

    loop {
        let data = drain_driver_messages(device, None, None);
        if let Some(data) = data {
            println!("Data: {data:#?}");
        }

        unsafe {
            Sleep(1000);
        }
    }
}

fn get_driver_handle_or_panic() -> HANDLE {
    unsafe {
        match CreateFileW(
            PCWSTR(driver_name().as_ptr()),
            GENERIC_ALL.0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_SYSTEM,
            None,
        ) {
            Ok(h) => h,
            Err(e) => panic!("Failed to open driver handle. {e}"),
        }
    }
}

fn driver_name() -> Vec<u16> {
    DRIVER_NAME.encode_utf16().chain(once(0)).collect()
}
