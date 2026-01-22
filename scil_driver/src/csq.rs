use core::{
    mem::MaybeUninit,
    ptr::{addr_of_mut, null_mut},
    sync::atomic::Ordering,
};

use wdk_sys::{
    _IO_CSQ, IO_CSQ, IO_NO_INCREMENT, IRP, KIRQL, LIST_ENTRY, NTSTATUS, PIO_CSQ, PIRP, PLIST_ENTRY,
    PVOID, STATUS_CANCELLED, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
    ntddk::{
        IofCompleteRequest, KeAcquireSpinLockRaiseToDpc, KeLowerIrql, KeReleaseSpinLockFromDpcLevel,
    },
};

use crate::SCIL_DRIVER_EXT;

#[allow(non_snake_case)]
pub unsafe extern "C" fn CsqInsertIrp(
    csq: *mut _IO_CSQ,
    irp: PIRP,
    _insert_context: PVOID,
) -> NTSTATUS {
    unsafe {
        let p_driver_ext = SCIL_DRIVER_EXT.load(Ordering::SeqCst);
        if p_driver_ext.is_null() {
            return STATUS_UNSUCCESSFUL;
        }

        //
        // Insert the irp to the tail, to act as a queue
        //
        InsertTailList(
            &raw mut ((*p_driver_ext).irp_queue_list),
            &raw mut ((*irp).Tail.Overlay.__bindgen_anon_2.ListEntry),
        );

        STATUS_SUCCESS
    }
}

#[allow(non_snake_case)]
pub unsafe extern "C" fn CsqAcquireLock(csq: PIO_CSQ, old_irql: *mut KIRQL) {
    unsafe {
        let p_scil_struct = SCIL_DRIVER_EXT.load(Ordering::SeqCst);
        if p_scil_struct.is_null() {
            return;
        }

        *old_irql = KeAcquireSpinLockRaiseToDpc(&mut (*p_scil_struct).csq_lock);
    }
}

#[allow(non_snake_case)]
pub unsafe extern "C" fn CsqReleaseLock(csq: PIO_CSQ, old_irql: KIRQL) {
    unsafe {
        let ext = SCIL_DRIVER_EXT.load(Ordering::SeqCst);
        if ext.is_null() {
            return;
        }

        KeReleaseSpinLockFromDpcLevel(&mut (*ext).csq_lock);
        KeLowerIrql(old_irql);
    }
}

#[allow(non_snake_case)]
pub unsafe extern "C" fn CsqCompleteCanceledIrp(_csq: PIO_CSQ, irp: PIRP) {
    unsafe {
        (*irp).IoStatus.__bindgen_anon_1.Status = STATUS_CANCELLED;
        (*irp).IoStatus.Information = 0;
        IofCompleteRequest(irp, IO_NO_INCREMENT as i8);
    }
}

#[allow(non_snake_case)]
pub unsafe extern "C" fn CsqRemoveIrp(_csq: PIO_CSQ, p_irp: PIRP) {
    unsafe {
        RemoveEntryList(&mut (*p_irp).Tail.Overlay.__bindgen_anon_2.ListEntry);
    }
}

#[inline(always)]
fn offset_of_irp_list_entry() -> usize {
    let uninit = MaybeUninit::<IRP>::uninit();
    let base = uninit.as_ptr() as usize;

    let field = unsafe {
        &(*uninit.as_ptr()).Tail.Overlay.__bindgen_anon_2.ListEntry as *const LIST_ENTRY as usize
    };

    field - base
}

#[inline(always)]
unsafe fn list_entry_to_irp(p_le: PLIST_ENTRY) -> PIRP {
    unsafe {
        let offset = offset_of_irp_list_entry();
        (p_le as *mut u8).offset(-(offset as isize)) as PIRP
    }
}

#[inline(always)]
unsafe fn irp_list_entry(irp: PIRP) -> PLIST_ENTRY {
    unsafe { &mut (*irp).Tail.Overlay.__bindgen_anon_2.ListEntry as *mut LIST_ENTRY }
}

#[allow(non_snake_case)]
/// SAFETY: Can return null
pub unsafe extern "C" fn CsqPeekNextIrp(csq: PIO_CSQ, irp: PIRP, _peek_context: PVOID) -> PIRP {
    unsafe {
        let p_device_ext = SCIL_DRIVER_EXT.load(Ordering::SeqCst);
        if p_device_ext.is_null() {
            return null_mut();
        }

        if IsListEmpty(&mut (*p_device_ext).irp_queue_list) {
            // no pending IRPs
            return null_mut();
        }

        let head: PLIST_ENTRY = addr_of_mut!((*p_device_ext).irp_queue_list);

        let list_entry_irp: PLIST_ENTRY = if !irp.is_null() {
            (*irp_list_entry(irp)).Flink
        } else {
            (*head).Flink
        };

        if list_entry_irp == head {
            return null_mut();
        }

        let p_irp = list_entry_to_irp(list_entry_irp);
        p_irp
    }
}
#[allow(non_snake_case)]
pub fn InsertTailList(list_head: PLIST_ENTRY, entry: PLIST_ENTRY) {
    unsafe {
        let blink = (*list_head).Blink;
        (*entry).Flink = list_head;
        (*entry).Blink = blink;
        (*blink).Flink = entry;
        (*list_head).Blink = entry;
    }
}

#[allow(non_snake_case)]
pub fn IsListEmpty(list_head: PLIST_ENTRY) -> bool {
    unsafe { (*list_head).Flink == list_head }
}

#[allow(non_snake_case)]
pub fn RemoveEntryList(p_le: PLIST_ENTRY) {
    unsafe {
        let flink = (*p_le).Flink;
        let blink = (*p_le).Blink;

        (*blink).Flink = flink;
        (*flink).Blink = blink;

        (*p_le).Flink = null_mut();
        (*p_le).Blink = null_mut();
    }
}
