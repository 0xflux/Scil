use alloc::{format, string::String, vec::Vec};
use core::mem::take;
use thiserror::Error;
use wdk::println;
use wdk_mutex::{errors::GrtError, grt::Grt};
use wdk_sys::{
    _LARGE_INTEGER,
    ntddk::{KeGetCurrentIrql, KeQuerySystemTimePrecise, RtlRandomEx},
};

#[derive(Debug)]
pub struct TelemetryEntry {
    uuid: uuid::Uuid,
    nt_function: NtFunction,
    args: Args,
    pid: u32,
    /// Time of the telemetry object being created
    time: i64,
}

impl TelemetryEntry {
    pub fn new(nt_function: NtFunction, args: Args, pid: u32) -> Self {
        //
        // Build the UUID, seeded by the current system time. This is acceptable enough for sufficient randomness
        // as we aren't doing anything crazy, just generating ID's
        //

        let mut big = _LARGE_INTEGER::default();
        unsafe {
            KeQuerySystemTimePrecise(&mut big);
        };

        let time = unsafe { big.QuadPart };

        let mut seed = unsafe { big.u.LowPart };
        let uuid_part_1 = unsafe { RtlRandomEx(&mut seed) };
        let uuid_part_2 = unsafe { RtlRandomEx(&mut seed) };
        let uuid_part_3 = unsafe { RtlRandomEx(&mut seed) };
        let uuid_part_4 = unsafe { RtlRandomEx(&mut seed) };

        //
        // shift into a u128 for the uuid crate and create the UUID object
        //
        let uuid_big_int: u128 = ((uuid_part_1 as u128) << 96)
            | ((uuid_part_2 as u128) << 64)
            | ((uuid_part_3 as u128) << 32)
            | ((uuid_part_4 as u128) << 0);

        let uuid = uuid::Builder::from_random_bytes(uuid_big_int.to_le_bytes()).into_uuid();

        Self {
            uuid,
            nt_function,
            args,
            pid,
            time,
        }
    }
}

#[derive(Debug)]
pub enum NtFunction {
    NtOpenProcess,
}

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

pub struct TelemetryCache;

#[derive(Error, Debug)]
pub enum TelemetryError {
    #[error("fast mutex failed to initialise, {0}")]
    FastMtxFail(String),
    #[error("failed to create a mutex via Grt")]
    GrtError(GrtError),
}

const TELEMETRY_MTX_KEY: &str = "SCIL_LOGGING";

impl TelemetryCache {
    /// Creates a new instance by registering a pool managed object behind the [`wdk_mutex`] runtime, with the key found in the
    /// const &'static str `TELEMETRY_MTX_KEY`.
    ///
    /// The function returns nothing, but the object can be accessed through the named key.
    pub fn new() -> Result<(), TelemetryError> {
        if let Err(e) =
            Grt::register_fast_mutex_checked(TELEMETRY_MTX_KEY, Vec::<TelemetryEntry>::new())
        {
            return Err(TelemetryError::GrtError(e));
        }

        Ok(())
    }

    pub fn default() -> Result<(), TelemetryError> {
        Self::new()
    }

    pub fn push(telemetry_entry: TelemetryEntry) -> Result<(), TelemetryError> {
        let h_mtx = match Grt::get_fast_mutex::<Vec<TelemetryEntry>>(TELEMETRY_MTX_KEY) {
            Ok(m) => m,
            Err(e) => {
                return Err(TelemetryError::GrtError(e));
            }
        };

        let Ok(mut lock) = h_mtx.lock() else {
            let irql = unsafe { KeGetCurrentIrql() };
            return Err(TelemetryError::FastMtxFail(format!(
                "Failed to lock mutex. IRQL is: {irql}"
            )));
        };

        lock.push(telemetry_entry);

        Ok(())
    }

    /// Drains the current cache, returning the drained data. The cache is then replaced with an empty set.
    pub fn drain() -> Result<Vec<TelemetryEntry>, TelemetryError> {
        let h_mtx = match Grt::get_fast_mutex::<Vec<TelemetryEntry>>(TELEMETRY_MTX_KEY) {
            Ok(m) => m,
            Err(e) => {
                return Err(TelemetryError::GrtError(e));
            }
        };

        let Ok(mut lock) = h_mtx.lock() else {
            let irql = unsafe { KeGetCurrentIrql() };
            return Err(TelemetryError::FastMtxFail(format!(
                "Failed to lock mutex. IRQL is: {irql}"
            )));
        };

        println!("[scil] [i] Len before take: {}", lock.len());
        // SAFETY: Could this MOVE the memory under the mutex? That would lead to UB / BSOD.. however, I do not think
        // this is actually creating a new pool allocation so, should be ok if its just emptying the actual Vec.
        let drained = take(&mut *lock);
        println!("[scil] [i] Len after take: {}", lock.len());

        Ok(drained)
    }
}
