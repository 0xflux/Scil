//! For enabling / disabling alt syscalls

use core::{
    arch::asm,
    ffi::{CStr, c_void},
    ptr::null_mut,
    slice,
    sync::atomic::{AtomicPtr, Ordering},
};

use alloc::{boxed::Box, collections::btree_map::BTreeMap, string::String};
use shared::telemetry::{
    Args, MonitoredExports, NtFunction, PartialContext, SSN_NT_ALLOCATE_VIRTUAL_MEMORY,
    SSN_NT_CONTINUE, SSN_NT_CONTINUE_EX, SSN_NT_CREATE_THREAD_EX, SSN_NT_OPEN_PROCESS,
    SSN_NT_WRITE_VM, TelemetryEntry, ssn_to_nt_function,
};
use uuid::Uuid;
use wdk::{nt_success, println};
use wdk_mutex::fast_mutex::FastMutex;
use wdk_sys::{
    _EVENT_TYPE::SynchronizationEvent,
    _KTRAP_FRAME,
    _KWAIT_REASON::Executive,
    _MEMORY_INFORMATION_CLASS::MemoryBasicInformation,
    _MODE::KernelMode,
    CLIENT_ID, DISPATCH_LEVEL, FALSE, IO_NO_INCREMENT, KAPC_STATE, KEVENT, KTRAP_FRAME,
    LARGE_INTEGER, MEMORY_BASIC_INFORMATION, MEMORY_INFORMATION_CLASS, PROCESS_ALL_ACCESS,
    PsProcessType, STATUS_SUCCESS, TRUE, UNICODE_STRING,
    ntddk::{
        IoCsqRemoveNextIrp, IoGetCurrentProcess, IofCompleteRequest, KeDelayExecutionThread,
        KeGetCurrentIrql, KeInitializeEvent, KeSetEvent, KeStackAttachProcess,
        KeUnstackDetachProcess, KeWaitForSingleObject, ObOpenObjectByPointer,
        RtlCopyMemoryNonTemporal, ZwClose, ZwQueryVirtualMemory,
    },
};

use crate::{
    SCIL_DRIVER_EXT,
    scil_telemetry::TelemetryEntryOrphan,
    utils::{DriverError, get_process_name_and_pid},
};

const NT_OPEN_FILE: u32 = 0x0033;
const NT_CREATE_SECTION: u32 = 0x004a;
const NT_CREATE_SECTION_EX: u32 = 0x00c6;
const NT_DEVICE_IO_CONTROL_FILE: u32 = 0x0007;
const NT_CREATE_FILE_SSN: u32 = 0x0055;
const NT_TRACE_EVENT_SSN: u32 = 0x005e;

pub type SyscallSuspendedPool = FastMutex<BTreeMap<Uuid, *mut KEVENT>>;

pub static SYSCALL_SUSPEND_POOL: AtomicPtr<SyscallSuspendedPool> = AtomicPtr::new(null_mut());

pub fn init_syscall_suspended_pool() -> Result<(), DriverError> {
    if SYSCALL_SUSPEND_POOL.load(Ordering::SeqCst).is_null() {
        let inner =
            SyscallSuspendedPool::new(BTreeMap::new()).map_err(|_| DriverError::MutexError)?;

        let boxed = Box::new(inner);
        let p_boxed = Box::into_raw(boxed);

        SYSCALL_SUSPEND_POOL.store(p_boxed, Ordering::SeqCst);
    }

    Ok(())
}

/// Drops the data owned by `SYSCALL_SUSPEND_POOL` and safely completes all threads such that the
/// system will not crash when the driver is stopped.
pub fn drop_syscall_suspended_pool() {
    let irql = unsafe { KeGetCurrentIrql() };
    let p = SYSCALL_SUSPEND_POOL.load(Ordering::SeqCst);

    if irql <= DISPATCH_LEVEL as u8 {
        if !p.is_null() {
            //
            // Allow all threads to resume by enumerating the waiting objects
            //

            let lock = unsafe { (*p).lock().unwrap() };
            for (_k, event) in (*lock).clone() {
                unsafe {
                    KeSetEvent(event, IO_NO_INCREMENT as _, FALSE as _);
                }
            }

            drop(lock);

            //
            // guard against use after frees by waiting until all trapped syscalls are completed
            //
            loop {
                let lock = unsafe { (*p).lock().unwrap() };
                if lock.is_empty() {
                    break;
                }
                drop(lock);

                println!("[scil] [i] Lock was not empty");
                unsafe {
                    let mut li = LARGE_INTEGER::default();
                    li.QuadPart = -10_000_000;
                    let _ = KeDelayExecutionThread(KernelMode as _, FALSE as _, &mut li);
                }
            }
        }
    } else {
        println!("[scil] [-] Bad IRQL when clearing syscall queue: {irql}");
    }

    let b = unsafe { Box::from_raw(p) };
    drop(b);
}

#[repr(C)]
struct KThreadLocalDef {
    junk: [u8; 0x90],
    k_trap_ptr: *mut KTRAP_FRAME,
}

const SYSCALL_ALLOW: i32 = 1;

/// The callback routine which we control to run when a system call is dispatched via the alt syscall technique.
///
/// # Args:
/// - `p_nt_function`: A function pointer to the real Nt* dispatch function (e.g. NtOpenProcess)
/// - `ssn`: The System Service Number of the syscall
/// - `args_base`: The base address of the args passed into the original syscall rcx, rdx, r8 and r9
/// - `p3_home`: The address of `P3Home` of the _KTRAP_FRAME
///
/// # Safety
/// This function is **NOT** compatible with the `PspSyscallProviderServiceDispatch` branch of alt syscalls, it
/// **WILL** result in a bug check in that instance. This can only be used with
/// `PspSyscallProviderServiceDispatchGeneric`.
pub unsafe extern "system" fn syscall_handler(
    _p_nt_function: c_void,
    ssn: u32,
    _args_base: *const c_void,
    _p3_home: *const c_void,
) -> i32 {
    let process_details = get_process_name_and_pid();
    let proc_name = process_details.0.to_lowercase();
    let pid = process_details.1;

    // We only want to target scil_test.exe as a POC
    if !proc_name.contains("scil_test") {
        return SYSCALL_ALLOW;
    }

    let ktrap_frame = match extract_trap() {
        Some(p) => unsafe { *p },
        None => {
            println!("[-] [scil] Could not get trap for syscall intercept.");
            return SYSCALL_ALLOW;
        }
    };

    match ssn {
        SSN_NT_OPEN_PROCESS
        | SSN_NT_ALLOCATE_VIRTUAL_MEMORY
        | SSN_NT_WRITE_VM
        | SSN_NT_CONTINUE
        | SSN_NT_CONTINUE_EX
        | SSN_NT_CREATE_THREAD_EX => {
            let Some(nt_fn) = ssn_to_nt_function(ssn) else {
                return SYSCALL_ALLOW;
            };

            // TODO this whole `if else if` needs abstracting.
            let nt_fn = if ssn == SSN_NT_OPEN_PROCESS {
                let p_client_id = ktrap_frame.R9 as *const CLIENT_ID;
                if !p_client_id.is_null() {
                    unsafe {
                        let ci = *p_client_id;
                        NtFunction::NtOpenProcess(ci.UniqueProcess as u32)
                    }
                } else {
                    NtFunction::NtOpenProcess(0)
                }
            } else if ssn == SSN_NT_CONTINUE || ssn == SSN_NT_CONTINUE_EX {
                unsafe {
                    let p_ctx = ktrap_frame.Rcx as *const PartialContext;

                    let p_process = IoGetCurrentProcess();
                    let mut p_apc_state = KAPC_STATE::default();

                    let mut context = PartialContext::default();

                    KeStackAttachProcess(p_process, &mut p_apc_state);

                    //
                    // Copy the context out of the NtContinue arg1 such that we will be able to send it
                    // back up to the user-mode EDR consumer.
                    //

                    RtlCopyMemoryNonTemporal(
                        &mut context as *mut _ as *mut _,
                        p_ctx as _,
                        size_of::<PartialContext>() as u64,
                    );

                    // Note logical OR check, we can allow execution without returning it back to user mode
                    if (context.Dr0 | context.Dr1 | context.Dr2 | context.Dr3) == 0 {
                        KeUnstackDetachProcess(&mut p_apc_state);
                        return SYSCALL_ALLOW;
                    }

                    //
                    // It is easier for us to determine whether the address maps to one that us as the 'Scil'
                    // would likely care about providing to an EDR vendor. We can use the Scil interface to
                    // determine if it is a bad address, and if so, pass it up to the user-mode consumer, without
                    // them having to do a lookup.
                    //
                    // For time saving - this should only be done where Dr0 - Dr3 is set for suspected VEH abuse.
                    // That check is done above.
                    //
                    // DEMO NOTE: We are only checking the register `Dr0` here, that is to save on time as my free time
                    // is precious. You can extend this by abstracting this into a function which checks all Dr0 - Dr3.
                    //

                    let mut handle = null_mut();
                    let mut status = ObOpenObjectByPointer(
                        p_process as _,
                        0,
                        null_mut(),
                        PROCESS_ALL_ACCESS,
                        *PsProcessType,
                        KernelMode as i8,
                        &mut handle,
                    );

                    if !nt_success(status) {
                        println!(
                            "[scil] [-] Failed to get a handle to the process. Error: {status:#X}"
                        );
                        KeUnstackDetachProcess(&mut p_apc_state);
                        return SYSCALL_ALLOW;
                    }

                    let mut mem_info = MEMORY_BASIC_INFORMATION::default();
                    let mut out_len: u64 = 0;

                    status = ZwQueryVirtualMemory(
                        handle,
                        context.Dr0 as _,
                        MemoryBasicInformation,
                        &mut mem_info as *mut _ as *mut c_void,
                        size_of::<MEMORY_BASIC_INFORMATION>() as u64,
                        &mut out_len,
                    );
                    if !nt_success(status) {
                        println!(
                            "[scil] [-] Failed to call ZwQueryVirtualMemory. Error: {status:#X}"
                        );
                        KeUnstackDetachProcess(&mut p_apc_state);
                        let _ = ZwClose(handle);
                        return SYSCALL_ALLOW;
                    }

                    let mut out_len: u64 = 0;
                    let mut path_buf = [0u8; 512];
                    // source https://docs.rs/ntapi/latest/ntapi/ntmmapi/constant.MemoryMappedFilenameInformation.html
                    #[allow(non_upper_case_globals)]
                    const MemoryMappedFilenameInformation: MEMORY_INFORMATION_CLASS = 2;

                    status = ZwQueryVirtualMemory(
                        handle,
                        context.Dr0 as _,
                        MemoryMappedFilenameInformation,
                        &mut path_buf as *mut _ as *mut c_void,
                        path_buf.len() as u64,
                        &mut out_len,
                    );
                    if !nt_success(status) {
                        println!(
                            "[scil] [-] Failed to call ZwQueryVirtualMemory 2nd time. Error: {status:#X}"
                        );
                        KeUnstackDetachProcess(&mut p_apc_state);
                        let _ = ZwClose(handle);
                        return SYSCALL_ALLOW;
                    }

                    let unicode = &*(path_buf.as_ptr() as *const UNICODE_STRING);

                    let module_name = if unicode.Length != 0 {
                        let s =
                            slice::from_raw_parts(unicode.Buffer, (unicode.Length as usize) / 2);
                        String::from_utf16_lossy(s)
                    } else {
                        String::from("Unknown")
                    };

                    // Note:
                    // Here we would extend the `Scil` subsystem to an internal API which can check against not only AMSI,
                    // but NTDLL, and any other exports & DLL's that the EDR wishes to register notification hooks for.
                    // TODO that would be fun (?) to build as part of the subsystem.
                    let mut maybe_abuse_function: Option<_> = None;
                    if module_name.to_ascii_lowercase().ends_with("amsi.dll") {
                        if let Some(name) = search_module_for_sensitive_addresses(
                            mem_info.AllocationBase,
                            context.Dr0 as *const _,
                        ) {
                            if name == "AmsiScanBuffer" {
                                maybe_abuse_function = Some(MonitoredExports::AmsiScanBuffer)
                            }
                        }
                    }

                    KeUnstackDetachProcess(&mut p_apc_state);

                    NtFunction::NtContinue((context, maybe_abuse_function))
                }
            } else if ssn == SSN_NT_WRITE_VM {
                let p_buf = ktrap_frame.R8 as *const c_void;
                let sz = ktrap_frame.R9 as usize;

                NtFunction::NtWriteVM((p_buf, sz))
            } else {
                nt_fn
            };

            let p_scil_object = SCIL_DRIVER_EXT.load(Ordering::SeqCst);
            if !p_scil_object.is_null() {
                let pirp = unsafe {
                    IoCsqRemoveNextIrp(&raw mut (*p_scil_object).cancel_safe_queue, null_mut())
                };

                if pirp.is_null() {
                    println!("[scil] [i] PIRP was null in syscall.");
                    return SYSCALL_ALLOW;
                }

                let te = TelemetryEntry::new(
                    nt_fn,
                    Args {
                        rcx: Some(ktrap_frame.Rcx as usize),
                        rdx: Some(ktrap_frame.Rdx as usize),
                        r8: Some(ktrap_frame.R8 as usize),
                        r9: Some(ktrap_frame.R9 as usize),
                        ..Default::default()
                    },
                    pid,
                );

                let data_sz = size_of::<TelemetryEntry>();
                unsafe { (*pirp).IoStatus.Information = data_sz as _ };

                unsafe {
                    RtlCopyMemoryNonTemporal(
                        (*pirp).AssociatedIrp.SystemBuffer,
                        &te as *const _ as *const c_void,
                        data_sz as _,
                    )
                };
                unsafe { (*pirp).IoStatus.__bindgen_anon_1.Status = STATUS_SUCCESS };

                //
                // Here we deal with suspending the thread using a NotificationEvent type of KEVENT,
                // in which we wait for the EDR running in VTL1 / PPL / our simulation normal process
                // to signal (via an IOCTL) that the process is ok to continue and the EDR has done its
                // jam. We can coordinate this by sticking the event into the pool and tracking the event
                // based on the event UUID we generated.
                //
                let mut k = KEVENT::default();
                unsafe {
                    KeInitializeEvent(&raw mut k, SynchronizationEvent, FALSE as u8);

                    {
                        let p_lock = SYSCALL_SUSPEND_POOL.load(Ordering::SeqCst);
                        if p_lock.is_null() {
                            println!(
                                "[scil] [-] SYSCALL_SUSPEND_POOL was null in syscall hot path!"
                            );
                            return SYSCALL_ALLOW;
                        }
                        let mut lock = match (*p_lock).lock() {
                            Ok(l) => l,
                            Err(e) => {
                                println!("[scil] [-] Failed to lock mtx in hot path. {e:?}");
                                return SYSCALL_ALLOW;
                            }
                        };

                        // Add the GUID and event into the pool
                        lock.insert(te.uuid, &raw mut k);
                    }

                    // Make sure we complete the request AFTER we insert the sync object to prevent a
                    // race
                    IofCompleteRequest(pirp, IO_NO_INCREMENT as i8);

                    let status = KeWaitForSingleObject(
                        &raw mut k as *mut _ as *mut _,
                        Executive as _,
                        KernelMode as _,
                        TRUE as _,
                        null_mut(),
                    );

                    {
                        let p_lock = SYSCALL_SUSPEND_POOL.load(Ordering::SeqCst);
                        if p_lock.is_null() {
                            println!(
                                "[scil] [-] SYSCALL_SUSPEND_POOL was null in syscall hot path after KeWait!"
                            );
                            return SYSCALL_ALLOW;
                        }
                        let mut lock = match (*p_lock).lock() {
                            Ok(l) => l,
                            Err(e) => {
                                println!(
                                    "[scil] [-] Failed to lock mtx in hot path after KeWait. {e:?}"
                                );
                                return SYSCALL_ALLOW;
                            }
                        };

                        lock.remove(&te.uuid);
                    }

                    if !nt_success(status) {
                        println!("[scil] [-] KeWait failed with sts: {status:#X}, ssn: {ssn:#X}");
                    }
                }
            }
        }
        _ => (),
    };

    SYSCALL_ALLOW
}

#[inline(always)]
fn extract_trap() -> Option<*const _KTRAP_FRAME> {
    let mut k_thread: *const c_void = null_mut();
    unsafe {
        asm!(
            "mov {}, gs:[0x188]",
            out(reg) k_thread,
        );
    }

    if k_thread.is_null() {
        println!("[-] [scil] No KTHREAD discovered.");
        return None;
    }

    let p_ktrap = unsafe { &*(k_thread as *const KThreadLocalDef) }.k_trap_ptr;

    Some(p_ktrap)
}

unsafe extern "system" {

    // https://codemachine.com/articles/top_ten_kernel_apis.html
    fn RtlFindExportedRoutineByName(
        dll_base: *const c_void,
        routine_name: *const u8,
    ) -> *const c_void;
}

const SENSITIVE_API_NAMES: [&[u8]; 5] = [
    b"AmsiScanBuffer\0",
    b"AmsiScanString\0",
    b"EtwEventWrite\0",
    b"EtwEventWriteFull\0",
    b"NtTraceEvent\0",
];

/// Searches through a **mapped** module in memory for a series of pre-defined functions that are protected against
/// Vectored Exception Handling abuse through the debug registers. This works against VEH^2 also which was researched
/// first by CrowdStrike.
///
/// # Safety
///
/// This function **MUST** be called whilst attached to a process stack via `KeStackAttachProcess` or it will Bug Check.
///
/// # Args
///
/// - `allocation_base`: The base address of the module you wish to search, with it being a **mapped** image.
/// - `target_address`: The address you are looking to see if it is a monitored, sensitive address.
unsafe fn search_module_for_sensitive_addresses(
    allocation_base: *const c_void,
    target_address: *const c_void,
) -> Option<String> {
    // Some safety..
    if allocation_base.is_null() || target_address.is_null() {
        return None;
    }

    //
    // Iterate through each API name we are monitoring and see if we get a match on the address
    //
    unsafe {
        for name in SENSITIVE_API_NAMES {
            let result = RtlFindExportedRoutineByName(allocation_base, name.as_ptr());
            if result.is_null() {
                continue;
            }

            //
            // Check whether the debug register is set on our API of concern
            //
            if result == target_address {
                let cstr = CStr::from_bytes_with_nul(name)
                    .unwrap_or(CStr::from_bytes_with_nul(b"Unknown\0").unwrap());

                return Some(cstr.to_string_lossy().into_owned());
            }
        }
    }

    None
}
