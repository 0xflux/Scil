use std::{collections::VecDeque, ffi::CStr, iter::once};

use shared::{
    DRIVER_NAME,
    telemetry::{EdrResult, NtFunction, SyscallAllowed, TelemetryEntry},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, GENERIC_ALL, GetLastError, HANDLE, MAX_PATH, WAIT_OBJECT_0},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_SYSTEM, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE,
            OPEN_EXISTING,
        },
        System::{
            Diagnostics::Debug::ReadProcessMemory,
            IO::GetOverlappedResult,
            ProcessStatus::GetModuleFileNameExA,
            Threading::{OpenProcess, PROCESS_ALL_ACCESS, Sleep, WaitForSingleObject},
        },
    },
    core::PCWSTR,
};

use crate::ioctl::{QueuedIoctl, drain_driver_messages, queue_ioctl, send_result_ioctl};

mod ioctl;

fn main() {
    println!("[i] Starting SCIL engine..");
    run_engine();
}

fn run_engine() {
    let device = get_driver_handle_or_panic();

    let mut queued_events = VecDeque::new();

    for _ in 0..1000 {
        let result = queue_ioctl(device);
        if let Ok(Some(r)) = result {
            queued_events.push_back(r);
        }
    }

    println!("[+] IOCTL pending buffers queued.");

    let _ = monitor_driver_intercept(device, &mut queued_events);

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
            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
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

/// Monitors the interception events from syscalls by the driver.
///
/// The function loops over all pending IRP's for a signalled event indicating one of them
/// has completed.
fn monitor_driver_intercept(
    device: HANDLE,
    pending: &mut VecDeque<Box<QueuedIoctl>>,
) -> Result<Vec<TelemetryEntry>, windows::core::Error> {
    let mut completed = Vec::new();

    while let Some(taken) = pending.pop_front() {
        let wait = unsafe { WaitForSingleObject(taken.event, 0) };

        // if the event is not complete, push it back and continue - which takes the next item
        if wait != WAIT_OBJECT_0 {
            pending.push_back(taken);
            continue;
        }

        let mut bytes: u32 = 0;
        unsafe {
            GetOverlappedResult(device, &taken.overlapped, &mut bytes, false)?;
            let _ = CloseHandle(taken.event);
        }

        // println!(
        //     "[i] Received intercepted syscall from process: {} function: {:?}, uuid: {}",
        //     taken.out.pid, taken.out.nt_function, taken.out.uuid
        // );

        match taken.out.nt_function {
            NtFunction::NtOpenProcess(pid) => {
                if pid != 0 {
                    println!("[i] Hooked process is trying to open pid: {pid}");
                    if let Ok(p_handle) = unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, pid) } {
                        let mut buf = [0u8; MAX_PATH as usize];
                        unsafe { GetModuleFileNameExA(Some(p_handle), None, &mut buf) };
                        let s = CStr::from_bytes_until_nul(&buf).unwrap();
                        println!(
                            "[i] Process was trying to open process image: {}",
                            s.to_str().unwrap()
                        );
                    }
                }
            }
            NtFunction::NtWriteVM((p_buf, sz)) => {
                println!("[i] Received event for NTWVM. p_buf: {p_buf:p}, sz: {sz}");
                let pid = taken.out.pid;
                unsafe {
                    let Ok(h_process) = OpenProcess(PROCESS_ALL_ACCESS, false, pid) else {
                        println!("[-] Could not open process, {:#X}", GetLastError().0);
                        break;
                    };

                    let mut buf = Vec::<u8>::with_capacity(sz);
                    let mut out_sz = 0;
                    if let Err(e) = ReadProcessMemory(
                        h_process,
                        p_buf,
                        buf.as_mut_ptr() as *mut u8 as _,
                        sz,
                        Some(&mut out_sz),
                    ) {
                        println!("[-] Error reading process memory of pid: {pid}: {e:?}");
                        break;
                    };

                    buf.set_len(out_sz);

                    if buf.starts_with(&[
                        0x31, 0xdb, 0x64, 0x8b, 0x7b, 0x30, 0x8b, 0x7f, 0x0c, 0x8b, 0x7f, 0x1c,
                        0x8b, 0x47, 0x08, 0x8b,
                    ]) {
                        println!("[!] Malware detected! Suspending process..");
                        loop {
                            Sleep(200);
                        }
                    }
                }
            }
            _ => (),
        }

        // println!("[i] Sending result to driver to release syscall.");
        let result = EdrResult {
            uuid: taken.out.uuid,
            allowed: SyscallAllowed::Yes,
        };
        send_result_ioctl(device, result);

        completed.push(taken.out);
    }

    Ok(completed)
}
