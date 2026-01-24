use std::{collections::VecDeque, iter::once};

use shared::{
    DRIVER_NAME,
    telemetry::{EdrResult, SyscallAllowed, TelemetryEntry},
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, GENERIC_ALL, HANDLE, WAIT_OBJECT_0},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_SYSTEM, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE,
            OPEN_EXISTING,
        },
        System::{
            IO::GetOverlappedResult,
            Threading::{Sleep, WaitForSingleObject},
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

    // TODO put on new thread, maybe a tokio select thereafter?
    let _ = monitor_driver_intercept(device, &mut queued_events);

    // TODO put on new thread, maybe a tokio select thereafter?
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

        println!(
            "[i] Received intercepted syscall from process: {} function: {:?}, uuid: {}",
            taken.out.pid, taken.out.nt_function, taken.out.uuid
        );

        println!("[i] Sending result to driver to release syscall.");
        let result = EdrResult {
            uuid: taken.out.uuid,
            allowed: SyscallAllowed::Yes,
        };
        send_result_ioctl(device, result);

        completed.push(taken.out);

        //
        // TODO now we need to push another pending ioctl into the driver; except maybe we want to do this immediately
        // after we pass the wait check for sp33d
        //
    }

    Ok(completed)
}
