use core::{ffi::c_void, ptr::null_mut, sync::atomic::Ordering};

use alloc::boxed::Box;
use shared::{
    AWAIT_PSO, IOCTL_DRAIN_LOG_SNAPSHOT, IOCTL_SNAPSHOT_QUE_LOG, telemetry::TelemetryEntry,
};
use wdk::println;
use wdk_mutex::{errors::DriverMutexError, fast_mutex::FastMutex};
use wdk_sys::{
    _IO_STACK_LOCATION, DEVICE_OBJECT, IO_NO_INCREMENT, NTSTATUS, PIRP, STATUS_BAD_DATA,
    STATUS_BUFFER_ALL_ZEROS, STATUS_INVALID_BUFFER_SIZE, STATUS_NOT_SUPPORTED, STATUS_PENDING,
    STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
    ntddk::{IofCompleteRequest, RtlCopyMemoryNonTemporal},
};

use crate::{
    G_PSO_IOCTL_QUEUE, PsoQueue, ffi::IoGetCurrentIrpStackLocation,
    scil_telemetry::SnapshottedTelemetryLog,
};

pub unsafe extern "C" fn handle_ioctl(_device: *mut DEVICE_OBJECT, pirp: PIRP) -> NTSTATUS {
    let p_stack_location: *mut _IO_STACK_LOCATION = unsafe { IoGetCurrentIrpStackLocation(pirp) };

    if p_stack_location.is_null() {
        println!("[scil] [-] Unable to get stack location for IRP.");
        return STATUS_UNSUCCESSFUL;
    }

    //
    // Receive any input data, WARNING this may be null
    //
    let mut ioctl_buffer = IoctlBuffer::new(p_stack_location, pirp);
    if let Err(e) = ioctl_buffer.receive() {
        println!("[scil] [-] Error receiving buffer: {e}");
        return e;
    }

    let return_status =
        match unsafe { (*p_stack_location).Parameters.DeviceIoControl.IoControlCode } {
            IOCTL_SNAPSHOT_QUE_LOG => {
                let count_items = match SnapshottedTelemetryLog::take_snapshot() {
                    Ok(r) => r,
                    Err(e) => {
                        println!("[scil] [-] Error dispatching IOCTL IOCTL_SNAPSHOT_QUE_LOG. {e}");
                        unsafe { IofCompleteRequest(pirp, IO_NO_INCREMENT as i8) };
                        return STATUS_UNSUCCESSFUL;
                    }
                };

                let data_sz = size_of::<usize>();
                unsafe { (*pirp).IoStatus.Information = data_sz as _ };

                unsafe {
                    RtlCopyMemoryNonTemporal(
                        (*pirp).AssociatedIrp.SystemBuffer,
                        &count_items as *const _ as *const c_void,
                        data_sz as _,
                    )
                };

                STATUS_SUCCESS
            }
            IOCTL_DRAIN_LOG_SNAPSHOT => {
                let input_data = ioctl_buffer.buf as *mut c_void as *mut usize;
                if input_data.is_null() {
                    println!("[scil] [-] Input buffer was null.");
                    unsafe { IofCompleteRequest(pirp, IO_NO_INCREMENT as i8) };
                    return STATUS_INVALID_BUFFER_SIZE;
                }

                let expected_snapshot_len = unsafe { *input_data };

                let drained_option =
                    match SnapshottedTelemetryLog::drain_snapshot(expected_snapshot_len) {
                        Ok(r) => r,
                        Err(e) => {
                            println!("[scil] [-] Error draining snapshot. {e}");
                            unsafe { IofCompleteRequest(pirp, IO_NO_INCREMENT as i8) };
                            return STATUS_UNSUCCESSFUL;
                        }
                    };

                let Some(drained_buf) = drained_option else {
                    println!("[scil] [-] There was no data to drain.");
                    unsafe { IofCompleteRequest(pirp, IO_NO_INCREMENT as i8) };
                    return STATUS_BAD_DATA;
                };

                let size_of_buf = drained_buf.len() * size_of::<TelemetryEntry>();
                unsafe { (*pirp).IoStatus.Information = size_of_buf as _ };

                unsafe {
                    RtlCopyMemoryNonTemporal(
                        (*pirp).AssociatedIrp.SystemBuffer,
                        drained_buf.as_ptr() as *const _ as *const c_void,
                        size_of_buf as _,
                    )
                };

                STATUS_SUCCESS
            }
            AWAIT_PSO => {
                //
                // Await the PSO (Pending Syscall Object) being available, then once it is via an event, return
                // the object to the calling thread in user-mode. The PSO will be a fixed size, and each event will
                // deal with only one syscall interrupt so we do not need a second call to deal with buffer size.
                //

                STATUS_PENDING
            }
            _ => STATUS_NOT_SUPPORTED,
        };

    // indicates that the caller has completed all processing for a given I/O request and
    // is returning the given IRP to the I/O manager
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocompleterequest
    unsafe { IofCompleteRequest(pirp, IO_NO_INCREMENT as i8) };

    return_status
}

pub fn init_pirp_queue() -> Result<(), DriverMutexError> {
    // Check it is not already registered.. ideally should return a more expressive error but fine for POC
    if G_PSO_IOCTL_QUEUE.load(Ordering::SeqCst).is_null() {
        let fm = Box::new(FastMutex::new(PsoQueue::new())?);
        let p_fm = Box::into_raw(fm);
        G_PSO_IOCTL_QUEUE.store(p_fm, Ordering::SeqCst);
    }

    Ok(())
}

pub fn drop_pirp_queue() {
    let p_queue = G_PSO_IOCTL_QUEUE.load(Ordering::SeqCst);
    if !p_queue.is_null() {
        let fm = unsafe { Box::from_raw(p_queue) };
        drop(fm);
        G_PSO_IOCTL_QUEUE.store(null_mut(), Ordering::SeqCst);
    }
}

fn queue_pso_ioctl(pirp: PIRP) {}

struct IoctlBuffer {
    len: u32,
    buf: *mut c_void,
    p_stack_location: *mut _IO_STACK_LOCATION,
    pirp: PIRP,
}

impl IoctlBuffer {
    /// Creates a new instance of the IOCTL buffer type
    fn new(p_stack_location: *mut _IO_STACK_LOCATION, pirp: PIRP) -> Self {
        IoctlBuffer {
            len: 0,
            buf: null_mut(),
            p_stack_location,
            pirp,
        }
    }

    /// Receives raw data from the IO Manager and checks the validity of the data. If the data was valid, it will set the member
    /// fields for the length, buffer, and raw pointers to the required structs.
    ///
    /// If you want to get a string out of an ioctl buffer, it would be better to call get_buf_to_str.
    ///
    /// # Returns
    ///
    /// Success: a IoctlBuffer which will hold the length and a pointer to the buffer
    ///
    /// Error: NTSTATUS
    fn receive(&mut self) -> Result<(), NTSTATUS> {
        // length of in buffer
        let input_len: u32 = unsafe {
            (*self.p_stack_location)
                .Parameters
                .DeviceIoControl
                .InputBufferLength
        };
        // if input_len == 0 {
        //     println!("IOCTL PING input length invalid.");
        //     return Err(STATUS_BUFFER_TOO_SMALL)
        // };

        // For METHOD_BUFFERED, the driver should use the buffer pointed to by Irp->AssociatedIrp.SystemBuffer as the output buffer.
        let input_buffer: *mut c_void = unsafe { (*self.pirp).AssociatedIrp.SystemBuffer };
        if input_buffer.is_null() {
            println!("Input buffer is null.");
            return Err(STATUS_BUFFER_ALL_ZEROS);
        };

        // validate the pointer
        if input_buffer.is_null() {
            println!("IOCTL input buffer was null.");
            return Err(STATUS_UNSUCCESSFUL);
        }

        self.len = input_len;
        self.buf = input_buffer;

        Ok(())
    }
}
