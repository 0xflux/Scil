#![no_std]

pub mod telemetry;

pub static NT_DEVICE_NAME: &str = "\\Device\\ScilDriver";
pub static DOS_DEVICE_NAME: &str = "\\??\\ScilDriver";
pub const DRIVER_NAME: &str = "\\\\.\\ScilDriver";

const FILE_DEVICE_UNKNOWN: u32 = 34u32;
const METHOD_NEITHER: u32 = 3u32;
const METHOD_BUFFERED: u32 = 0u32;
const FILE_ANY_ACCESS: u32 = 0u32;

macro_rules! CTL_CODE {
    ($DeviceType:expr, $Function:expr, $Method:expr, $Access:expr) => {
        ($DeviceType << 16) | ($Access << 14) | ($Function << 2) | $Method
    };
}

/// Drains the snapshotted messages from the SCIL signals
pub const IOCTL_DRAIN_LOG_SNAPSHOT: u32 =
    CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// Snapshots the current queue, returning the count of queued items
pub const IOCTL_SNAPSHOT_QUE_LOG: u32 =
    CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// Awaits a PSO (Pending Syscall Object) event being handled
pub const AWAIT_PSO: u32 =
    CTL_CODE!(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS);