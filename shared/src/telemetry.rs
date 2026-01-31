use core::{default, ffi::c_void, mem::zeroed, ptr::null_mut};

use uuid::Uuid;

#[repr(C)]
#[derive(Debug, Default)]
pub struct TelemetryEntry {
    pub uuid: uuid::Uuid,
    pub nt_function: NtFunction,
    pub args: Args,
    pub pid: u32,
    /// Time of the telemetry object being created
    pub time: i64,
}

/// Inner type for NtWriteVirtualMemory:
/// - Ptr to the allocation
/// - Sz of allocation
pub type NtWVMInner = (*const c_void, usize);

#[repr(C)]
#[derive(Debug)]
#[allow(non_snake_case)]
pub struct FLOATING_SAVE_AREA {
    pub ControlWord: u32,
    pub StatusWord: u32,
    pub TagWord: u32,
    pub ErrorOffset: u32,
    pub ErrorSelector: u32,
    pub DataOffset: u32,
    pub DataSelector: u32,
    pub RegisterArea: [u8; 80],
    pub Spare0: u32,
}

impl Default for FLOATING_SAVE_AREA {
    fn default() -> Self {
        Self {
            ControlWord: Default::default(),
            StatusWord: Default::default(),
            TagWord: Default::default(),
            ErrorOffset: Default::default(),
            ErrorSelector: Default::default(),
            DataOffset: Default::default(),
            DataSelector: Default::default(),
            RegisterArea: [0; 80],
            Spare0: Default::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Default)]
#[allow(non_snake_case)]
pub struct PartialContext {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: u32,
    pub MxCsr: u32,
    pub SegCs: u16,
    pub SegDs: u16,
    pub SegEs: u16,
    pub SegFs: u16,
    pub SegGs: u16,
    pub SegSs: u16,
    pub EFlags: u32,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
}

#[repr(C)]
#[derive(Debug)]
pub enum MonitoredExports {
    AmsiScanBuffer,
    AmsiScanString,
    EtwEventWrite,
    EtwEventWriteFull,
    // .. etc
}

pub type NtContinueInner = (PartialContext, Option<MonitoredExports>);

#[repr(C)]
#[derive(Debug, Default)]
pub enum NtFunction {
    NtOpenProcess(u32),
    #[default]
    NtAllocateVM,
    NtCreateThreadEx,
    NtWriteVM(NtWVMInner),
    NtContinue(NtContinueInner),
    NtContinueEx(NtContinueInner),
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct Args {
    pub rcx: Option<usize>,
    pub rdx: Option<usize>,
    pub r8: Option<usize>,
    pub r9: Option<usize>,
    pub stack1: Option<usize>,
    pub stack2: Option<usize>,
    pub stack3: Option<usize>,
    pub stack4: Option<usize>,
    pub stack5: Option<usize>,
    pub stack6: Option<usize>,
    pub stack7: Option<usize>,
}

pub const SSN_NT_OPEN_PROCESS: u32 = 0x26;
pub const SSN_NT_ALLOCATE_VIRTUAL_MEMORY: u32 = 0x18;
pub const SSN_NT_CREATE_THREAD_EX: u32 = 0x00c9;
pub const SSN_NT_WRITE_VM: u32 = 0x003a;
pub const SSN_NT_CONTINUE: u32 = 0x0043;
pub const SSN_NT_CONTINUE_EX: u32 = 0x00a5; // valid for 25H2

pub fn ssn_to_nt_function(ssn: u32) -> Option<NtFunction> {
    match ssn {
        SSN_NT_OPEN_PROCESS => Some(NtFunction::NtOpenProcess(0)),
        SSN_NT_ALLOCATE_VIRTUAL_MEMORY => Some(NtFunction::NtAllocateVM),
        SSN_NT_CREATE_THREAD_EX => Some(NtFunction::NtCreateThreadEx),
        SSN_NT_WRITE_VM => Some(NtFunction::NtWriteVM((null_mut(), 0))),
        SSN_NT_CONTINUE => Some(NtFunction::NtContinue(unsafe { zeroed() })),
        SSN_NT_CONTINUE_EX => Some(NtFunction::NtContinue(unsafe { zeroed() })),
        _ => None,
    }
}

#[derive(Default, Debug)]
pub enum SyscallAllowed {
    #[default]
    Yes,
    No,
}

#[repr(C)]
#[derive(Default)]
pub struct EdrResult {
    pub uuid: Uuid,
    pub allowed: SyscallAllowed,
}
