use std::ffi::c_void;

use shared::{
    AWAIT_PSO, IOCTL_DRAIN_LOG_SNAPSHOT, IOCTL_SNAPSHOT_QUE_LOG, telemetry::TelemetryEntry,
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_IO_PENDING, HANDLE},
        System::{
            IO::{DeviceIoControl, OVERLAPPED},
            Threading::CreateEventW,
        },
    },
    core::HRESULT,
};

pub struct QueuedIoctl {
    pub out: TelemetryEntry,
    pub overlapped: OVERLAPPED,
    pub event: HANDLE,
}

pub fn queue_ioctl(device: HANDLE) -> Result<Option<Box<QueuedIoctl>>, windows::core::Error> {
    let event = unsafe { CreateEventW(None, false, false, None)? };

    let mut b = Box::new(QueuedIoctl {
        out: TelemetryEntry::default(),
        overlapped: OVERLAPPED::default(),
        event,
    });

    b.overlapped.hEvent = b.event;

    let status = unsafe {
        DeviceIoControl(
            device,
            AWAIT_PSO,
            None,
            0,
            Some(&mut b.out as *mut _ as _),
            size_of::<TelemetryEntry>() as u32,
            None,
            Some(&mut b.overlapped),
        )
    };

    match status {
        Ok(()) => {
            println!("[i] IOCTL completed immediately");
            unsafe {
                let _ = CloseHandle(event);
            }
            return Ok(None);
        }
        Err(e) => {
            let code: HRESULT = e.code();

            if code != ERROR_IO_PENDING.to_hresult() {
                unsafe {
                    let _ = CloseHandle(event);
                }
                println!("[-] DeviceIoControl failed: {e:?}");
                return Err(e);
            }
        }
    }

    return Ok(Some(b));
}

/// Makes an IOCTL to drain the driver messages. If no buffer is taken by this function, then
/// the function calls to get the count.
pub fn drain_driver_messages(
    device: HANDLE,
    maybe_buf: Option<Vec<TelemetryEntry>>,
    maybe_num_elements: Option<usize>,
) -> Option<Vec<TelemetryEntry>> {
    //
    // If the function is called with None, then we need to get the size of the buffer and have the
    // driver create a snapshot of the data.
    // This branch will then recursively call the current function to retrieve the data from the driver.
    //
    let Some(mut buf) = maybe_buf else {
        let mut count_items = 0usize;

        if let Err(e) = unsafe {
            DeviceIoControl(
                device,
                IOCTL_SNAPSHOT_QUE_LOG,
                None,
                0,
                Some(&mut count_items as *mut usize as *mut c_void),
                size_of_val(&count_items) as u32,
                None,
                None,
            )
        } {
            println!(
                "[-] Failed to make IOCTL for IOCTL_SNAPSHOT_QUE_LOG where buffer was not yet initialised. {e}"
            );
            return None;
        };

        // Nothing queued
        if count_items == 0 {
            return None;
        }

        let buf = Vec::<TelemetryEntry>::with_capacity(count_items);

        return drain_driver_messages(device, Some(buf), Some(count_items));
    };

    let Some(num_elements) = maybe_num_elements else {
        return None;
    };

    //
    // Calculate the actual size of the buffer and make the IOCTL again, this time draining the snapshot
    //
    let sz = size_of::<TelemetryEntry>() * num_elements;

    if let Err(e) = unsafe {
        DeviceIoControl(
            device,
            IOCTL_DRAIN_LOG_SNAPSHOT,
            Some(&num_elements as *const usize as _),
            size_of::<usize>() as _,
            Some(buf.as_mut_ptr() as *mut _ as *mut c_void),
            sz as u32,
            None,
            None,
        )
    } {
        println!(
            "[-] Failed to make IOCTL for IOCTL_DRAIN_LOG_SNAPSHOT where buffer was initialised with len: {}. {e}",
            buf.len()
        );
        return None;
    };

    // SAFETY: We fill the buffer manually through the IOCTL, so we just need to set the length
    unsafe { buf.set_len(num_elements) };

    Some(buf)
}
