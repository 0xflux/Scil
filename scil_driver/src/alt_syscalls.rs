//! For enabling / disabling alt syscalls

use core::{
    arch::asm,
    ffi::c_void,
    ptr::null_mut,
    sync::atomic::{AtomicPtr, Ordering},
};

use alloc::{boxed::Box, collections::btree_map::BTreeMap};
use shared::telemetry::{
    Args, SSN_NT_ALLOCATE_VIRTUAL_MEMORY, SSN_NT_CREATE_THREAD_EX, SSN_NT_OPEN_PROCESS,
    SSN_NT_WRITE_VM, TelemetryEntry, ssn_to_nt_function,
};
use uuid::Uuid;
use wdk::{nt_success, println};
use wdk_mutex::fast_mutex::FastMutex;
use wdk_sys::{
    _EVENT_TYPE::SynchronizationEvent,
    _KTRAP_FRAME,
    _KWAIT_REASON::Executive,
    _MODE::KernelMode,
    DISPATCH_LEVEL, FALSE, IO_NO_INCREMENT, KEVENT, KTRAP_FRAME, LARGE_INTEGER, STATUS_SUCCESS,
    TRUE,
    ntddk::{
        IoCsqRemoveNextIrp, IofCompleteRequest, KeDelayExecutionThread, KeGetCurrentIrql,
        KeInitializeEvent, KeSetEvent, KeWaitForSingleObject, RtlCopyMemoryNonTemporal,
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
        | SSN_NT_CREATE_THREAD_EX => {
            let Some(nt_fn) = ssn_to_nt_function(ssn) else {
                return SYSCALL_ALLOW;
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

                    println!("[scil] [i] Now waiting on single object for SSN: {ssn:#X}");

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

                    println!("[scil] [+] Wait finished ssn: {ssn:#X}");
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
