use core::default;

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

#[repr(C)]
#[derive(Debug, Default)]
pub enum NtFunction {
    #[default]
    NtOpenProcess,
    NtAllocateVM,
    NtCreateThreadEx,
    NtWriteVM,
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

pub fn ssn_to_nt_function(ssn: u32) -> Option<NtFunction> {
    match ssn {
        SSN_NT_OPEN_PROCESS => Some(NtFunction::NtOpenProcess),
        SSN_NT_ALLOCATE_VIRTUAL_MEMORY => Some(NtFunction::NtAllocateVM),
        SSN_NT_CREATE_THREAD_EX => Some(NtFunction::NtCreateThreadEx),
        SSN_NT_WRITE_VM => Some(NtFunction::NtWriteVM),
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
