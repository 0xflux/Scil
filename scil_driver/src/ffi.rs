use core::ffi::c_void;

use wdk_sys::{ACCESS_MASK, HANDLE, NTSTATUS, PHANDLE, PIO_STACK_LOCATION, PIRP, PULONG, ULONG};

unsafe extern "system" {
    pub unsafe fn PsGetProcessImageFileName(p_eprocess: *const c_void) -> *const c_void;
    pub unsafe fn NtQueryInformationProcess(
        handle: HANDLE,
        flags: i32,
        process_information: *mut c_void,
        len: ULONG,
        return_len: PULONG,
    ) -> NTSTATUS;

    pub unsafe fn ZwGetNextProcess(
        handle: HANDLE,
        access: ACCESS_MASK,
        attr: ULONG,
        flags: ULONG,
        new_proc_handle: PHANDLE,
    ) -> NTSTATUS;

    pub unsafe fn ZwGetNextThread(
        proc_handle: HANDLE,
        thread_handle: HANDLE,
        access: ACCESS_MASK,
        attr: ULONG,
        flags: ULONG,
        new_thread_handle: PHANDLE,
    ) -> NTSTATUS;
}

pub unsafe fn IoGetCurrentIrpStackLocation(irp: PIRP) -> PIO_STACK_LOCATION {
    unsafe {
        assert!((*irp).CurrentLocation <= (*irp).StackCount + 1);
        (*irp)
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation
    }
}
