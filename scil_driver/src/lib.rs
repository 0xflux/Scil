#![no_std]
#![feature(map_try_insert)]
extern crate alloc;

use alloc::{boxed::Box, vec::Vec};
use core::{
    iter::once,
    mem::zeroed,
    ptr::null_mut,
    sync::atomic::{AtomicI32, AtomicPtr, Ordering},
};
use shared::{DOS_DEVICE_NAME, NT_DEVICE_NAME};
use wdk::{nt_success, println};
use wdk_mutex::grt::Grt;
use wdk_sys::{
    DEVICE_OBJECT, DO_BUFFERED_IO, DRIVER_OBJECT, FILE_DEVICE_SECURE_OPEN, FILE_DEVICE_UNKNOWN,
    IO_CSQ, IO_NO_INCREMENT, IRP_MJ_CLOSE, IRP_MJ_CREATE, IRP_MJ_DEVICE_CONTROL, KSPIN_LOCK,
    LIST_ENTRY, NTSTATUS, PCUNICODE_STRING, PDEVICE_OBJECT, PIRP, PLIST_ENTRY, PUNICODE_STRING,
    STATUS_SUCCESS, STATUS_UNSUCCESSFUL, UNICODE_STRING,
    ntddk::{
        IoCreateDevice, IoCreateSymbolicLink, IoCsqInitializeEx, IoDeleteDevice,
        IoDeleteSymbolicLink, IofCompleteRequest, KeInitializeSpinLock,
        PsRemoveCreateThreadNotifyRoutine, PsRemoveLoadImageNotifyRoutine,
        PsSetCreateThreadNotifyRoutine, PsSetLoadImageNotifyRoutine, RtlInitUnicodeString,
    },
};

mod alt_syscalls;
mod callbacks;
mod csil_api;
mod csq;
mod ffi;
mod ioctl;
mod scil_telemetry;
mod utils;

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

use crate::{
    alt_syscalls::AltSyscalls,
    callbacks::{image_load_callback, thread_callback},
    csq::{
        CsqAcquireLock, CsqCompleteCanceledIrp, CsqInsertIrp, CsqPeekNextIrp, CsqReleaseLock,
        CsqRemoveIrp,
    },
    ioctl::handle_ioctl,
    scil_telemetry::TelemetryCache,
};

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

#[repr(C)]
// Layout taken from https://github.com/OmarShehata11/MySoundDriver/blob/master/MySoundDriver/Header.h
pub struct ScilDriverExtension {
    /// List for our queue of the Irp, it's the List entry point (Head)
    pub irp_queue_list: LIST_ENTRY,
    /// Structure for Cancel-safe queue to specify the IRP queue routines
    pub cancel_safe_queue: IO_CSQ,
    /// Spin lock for locking the Csq
    pub csq_lock: KSPIN_LOCK,
    /// Number of Irps in the queue in pending state
    pub num_queued_irps: AtomicI32,
}

pub static SCIL_DRIVER_EXT: AtomicPtr<ScilDriverExtension> = AtomicPtr::new(null_mut());

#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver: &mut DRIVER_OBJECT,
    registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    println!("[scil] [i] Starting SCIL driver.");

    //
    // Configure the WDM setup stuff
    //
    let status = unsafe { configure_driver(driver, registry_path as _) };
    if !nt_success(status) {
        println!("[scil] [-] Driver did not configure correctly.");
        return status;
    }

    //
    // SCIL driver specific setup for our internals
    //

    // Set up wdk-mutex
    if let Err(e) = Grt::init() {
        println!("Error creating Grt!: {:?}", e);
        return STATUS_UNSUCCESSFUL;
    }

    // Set up the telemetry system
    if let Err(e) = TelemetryCache::new() {
        println!("[scil] [-] Failed to create Telemetry Cache. {e:?}");
        driver_exit(driver);
        return STATUS_UNSUCCESSFUL;
    };

    // Alt syscalls
    AltSyscalls::initialise_for_system(driver);

    // Image load callbacks
    if !nt_success(unsafe { PsSetLoadImageNotifyRoutine(Some(image_load_callback)) }) {
        println!("[scil] [-] Failed to register image load callbacks");
        driver_exit(driver);
        return STATUS_UNSUCCESSFUL;
    }

    // Thread create callbacks
    if !nt_success(unsafe { PsSetCreateThreadNotifyRoutine(Some(thread_callback)) }) {
        println!("[scil] [-] Failed to register thread create callbacks");
        driver_exit(driver);
        return STATUS_UNSUCCESSFUL;
    }

    STATUS_SUCCESS
}

extern "C" fn driver_exit(driver: *mut DRIVER_OBJECT) {
    //
    // Destroy driver internals
    //

    let _ = unsafe { Grt::destroy() };
    AltSyscalls::uninstall();
    let _ = unsafe { PsRemoveLoadImageNotifyRoutine(Some(image_load_callback)) };
    let _ = unsafe { PsRemoveCreateThreadNotifyRoutine(Some(thread_callback)) };

    let raw_p = SCIL_DRIVER_EXT.load(Ordering::SeqCst);
    if !raw_p.is_null() {
        let p = unsafe { Box::from_raw(raw_p) };
        drop(p);
    }

    //
    // Delete the driver object
    //

    let mut dos_name = UNICODE_STRING::default();
    let dos_name_u16: Vec<u16> = DOS_DEVICE_NAME.encode_utf16().chain(once(0)).collect();
    unsafe {
        RtlInitUnicodeString(&mut dos_name, dos_name_u16.as_ptr());
    }
    let _ = unsafe { IoDeleteSymbolicLink(&mut dos_name) };

    unsafe {
        IoDeleteDevice((*driver).DeviceObject);
    }

    println!("[scil] [i] Driver exit complete.");
}

pub unsafe extern "C" fn configure_driver(
    driver: &mut DRIVER_OBJECT,
    _registry_path: PUNICODE_STRING,
) -> NTSTATUS {
    //
    // Configure the strings required for symbolic links and naming
    //
    let mut dos_name = UNICODE_STRING::default();
    let mut nt_name = UNICODE_STRING::default();

    let dos_name_u16: Vec<u16> = DOS_DEVICE_NAME.encode_utf16().chain(once(0)).collect();
    let device_name_u16: Vec<u16> = NT_DEVICE_NAME.encode_utf16().chain(once(0)).collect();

    unsafe { RtlInitUnicodeString(&mut dos_name, dos_name_u16.as_ptr()) };
    unsafe { RtlInitUnicodeString(&mut nt_name, device_name_u16.as_ptr()) };

    //
    // Create the device
    //
    let mut device_object: PDEVICE_OBJECT = null_mut();

    let res = unsafe {
        IoCreateDevice(
            driver,
            0,
            &mut nt_name,
            FILE_DEVICE_UNKNOWN, // If a type of hardware does not match any of the defined types, specify a value of either FILE_DEVICE_UNKNOWN
            FILE_DEVICE_SECURE_OPEN,
            0,
            &mut device_object,
        )
    };
    if !nt_success(res) {
        println!("[scil] [-] Unable to create device via IoCreateDevice. Failed with code: {res}.");
        driver_exit(driver); // cleanup any resources before returning
        return res;
    }

    //
    // Initialise the device extension for the Csq
    //
    unsafe {
        let mut device_ext = Box::new(ScilDriverExtension {
            irp_queue_list: zeroed(),
            cancel_safe_queue: zeroed(),
            csq_lock: 0,
            num_queued_irps: AtomicI32::new(0),
        });

        InitializeListHead(&raw mut device_ext.irp_queue_list);
        KeInitializeSpinLock(&raw mut device_ext.csq_lock);

        let result = IoCsqInitializeEx(
            &raw mut device_ext.cancel_safe_queue,
            Some(CsqInsertIrp),
            Some(CsqRemoveIrp),
            Some(CsqPeekNextIrp),
            Some(CsqAcquireLock),
            Some(CsqReleaseLock),
            Some(CsqCompleteCanceledIrp),
        );

        if !nt_success(result) {
            println!("[scil] [-] Failed to initialise Csq. {result:#X}");
            return result;
        }

        // SAFETY: The size of the box does not change over time as all types are fixed
        // sizes that cannot grow, so turning this into a raw pointer is safe.
        let p_device_ext = Box::into_raw(device_ext);
        SCIL_DRIVER_EXT.store(p_device_ext, Ordering::SeqCst);
    }

    //
    // Create the symbolic link
    //
    let res = unsafe { IoCreateSymbolicLink(&mut dos_name, &mut nt_name) };
    if res != 0 {
        println!("[scil] [-] Failed to create driver symbolic link. Error: {res}");

        driver_exit(driver); // cleanup any resources before returning
        return STATUS_UNSUCCESSFUL;
    }

    //
    // Configure the drivers general callbacks
    //
    driver.MajorFunction[IRP_MJ_CREATE as usize] = Some(scil_create_close); // todo can authenticate requests coming from x
    driver.MajorFunction[IRP_MJ_CLOSE as usize] = Some(scil_create_close);
    driver.MajorFunction[IRP_MJ_DEVICE_CONTROL as usize] = Some(handle_ioctl);
    driver.DriverUnload = Some(driver_exit);

    // Specifies the type of buffering that is used by the I/O manager for I/O requests that are sent to the device stack.
    (unsafe { *device_object }).Flags |= DO_BUFFERED_IO;

    STATUS_SUCCESS
}

unsafe extern "C" fn scil_create_close(_device: *mut DEVICE_OBJECT, pirp: PIRP) -> NTSTATUS {
    unsafe {
        (*pirp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS;
        (*pirp).IoStatus.Information = 0;
        IofCompleteRequest(pirp, IO_NO_INCREMENT as i8);
    }

    STATUS_SUCCESS
}

#[inline(always)]
#[allow(non_snake_case)]
unsafe fn InitializeListHead(p_le: PLIST_ENTRY) {
    unsafe {
        (*p_le).Flink = p_le;
        (*p_le).Blink = p_le;
    }
}
