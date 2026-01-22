use core::{ffi::c_void, ptr::null_mut, sync::atomic::Ordering};

use alloc::boxed::Box;
use shared::{
    AWAIT_PSO, IOCTL_DRAIN_LOG_SNAPSHOT, IOCTL_SNAPSHOT_QUE_LOG,
    telemetry::{Args, TelemetryEntry},
};
use wdk::{nt_success, println};
use wdk_mutex::{errors::DriverMutexError, fast_mutex::FastMutex};
use wdk_sys::{
    _IO_STACK_LOCATION, DEVICE_OBJECT, IO_NO_INCREMENT, NTSTATUS, PIRP, SL_PENDING_RETURNED,
    STATUS_BAD_DATA, STATUS_BUFFER_ALL_ZEROS, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_BUFFER_SIZE,
    STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_PENDING, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL,
    ntddk::{IoCsqInsertIrp, IoCsqInsertIrpEx, IofCompleteRequest, RtlCopyMemoryNonTemporal},
};

use crate::{
    SCIL_DRIVER_EXT, ScilDriverExtension, csq::CsqInsertIrp, ffi::IoGetCurrentIrpStackLocation,
    scil_telemetry::SnapshottedTelemetryLog,
};

pub unsafe extern "C" fn handle_ioctl(device: *mut DEVICE_OBJECT, pirp: PIRP) -> NTSTATUS {
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
                return unsafe { queue_pso_ioctl(ioctl_buffer, device) };
            }
            _ => STATUS_NOT_SUPPORTED,
        };

    // indicates that the caller has completed all processing for a given I/O request and
    // is returning the given IRP to the I/O manager
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocompleterequest
    unsafe { IofCompleteRequest(pirp, IO_NO_INCREMENT as i8) };

    return_status
}

/// If the state is valid, the function will deal with queuing
///
/// # Safety
///
/// On failure, this function will **complete** the IRP request, and therefore, it must NOT be allowed to
/// complete after this function returns other than in the happy path where it completes after getting data
/// from a buffer.
///
/// Callers of this function must ensure you return from its call stack WITHOUT calling `IofCompleteRequest`,
/// unless you have dealt with the event that causes the IRP to complete.
unsafe fn queue_pso_ioctl(ioctl_buffer: IoctlBuffer, _p_device: *mut DEVICE_OBJECT) -> NTSTATUS {
    let p_device_ext = SCIL_DRIVER_EXT.load(Ordering::SeqCst);
    if p_device_ext.is_null() {
        println!("[scil] [-] SCIL_DRIVER_EXT was unexpectedly null.");
        unsafe { (*ioctl_buffer.pirp).IoStatus.__bindgen_anon_1.Status = STATUS_INVALID_PARAMETER };
        unsafe { IofCompleteRequest(ioctl_buffer.pirp, IO_NO_INCREMENT as i8) };
        return STATUS_INVALID_PARAMETER;
    }

    if ioctl_buffer.p_stack_location.is_null() || ioctl_buffer.pirp.is_null() {
        println!("[scil] [-] PIRP was null in AWAIT_PSO.");
        unsafe { (*ioctl_buffer.pirp).IoStatus.__bindgen_anon_1.Status = STATUS_INVALID_PARAMETER };
        unsafe { IofCompleteRequest(ioctl_buffer.pirp, IO_NO_INCREMENT as i8) };
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Before we go ahead and stick the pirp in the queue, validate the buffer size is what we
    // expect for the return data
    //
    let user_buf_len = unsafe {
        (*ioctl_buffer.p_stack_location)
            .Parameters
            .DeviceIoControl
            .OutputBufferLength
    } as usize;

    if user_buf_len < size_of::<Args>() {
        println!("[scil] [-] User buffer was too small.");
        unsafe { (*ioctl_buffer.pirp).IoStatus.__bindgen_anon_1.Status = STATUS_BUFFER_TOO_SMALL };
        unsafe { IofCompleteRequest(ioctl_buffer.pirp, IO_NO_INCREMENT as i8) };
        return STATUS_BUFFER_TOO_SMALL;
    }

    let status = unsafe {
        IoCsqInsertIrpEx(
            &raw mut (*p_device_ext).cancel_safe_queue,
            ioctl_buffer.pirp,
            null_mut(),
            null_mut(),
        )
    };

    if !nt_success(status) {
        println!("[scil] [-] Failed to push Irp to Csq. Error: {status:#?}");
        unsafe { (*ioctl_buffer.pirp).IoStatus.__bindgen_anon_1.Status = status };
        unsafe { IofCompleteRequest(ioctl_buffer.pirp, IO_NO_INCREMENT as i8) };
        return STATUS_UNSUCCESSFUL;
    }

    unsafe {
        (*p_device_ext)
            .num_queued_irps
            .fetch_add(1, Ordering::SeqCst);
    }

    println!("[scil] [i] Queued IRPs after: {}", unsafe {
        (*p_device_ext).num_queued_irps.load(Ordering::SeqCst)
    });

    IoMarkIrpPending(ioctl_buffer.pirp);
    unsafe { (*ioctl_buffer.pirp).IoStatus.__bindgen_anon_1.Status = STATUS_PENDING };

    STATUS_PENDING
}

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

#[allow(non_snake_case)]
pub(crate) fn IoMarkIrpPending(irp: PIRP) {
    (unsafe { *IoGetCurrentIrpStackLocation(irp) }).Control |= SL_PENDING_RETURNED as u8;
}
