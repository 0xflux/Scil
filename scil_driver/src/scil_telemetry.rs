use alloc::{format, string::String, vec::Vec};
use core::{
    mem::take,
    sync::atomic::{AtomicBool, Ordering},
};
use shared::telemetry::{Args, NtFunction, TelemetryEntry};
use thiserror::Error;
use wdk::println;
use wdk_mutex::{errors::GrtError, grt::Grt};
use wdk_sys::{
    _LARGE_INTEGER,
    ntddk::{KeGetCurrentIrql, KeQuerySystemTimePrecise, RtlRandomEx},
};

pub trait TelemetryEntryOrphan {
    fn new(nt_function: NtFunction, args: Args, pid: u32) -> Self;
}

impl TelemetryEntryOrphan for TelemetryEntry {
    fn new(nt_function: NtFunction, args: Args, pid: u32) -> Self {
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

pub struct TelemetryCache;

#[derive(Error, Debug)]
pub enum TelemetryError {
    #[error("fast mutex failed to initialise, {0}")]
    FastMtxFail(String),
    #[error("failed to create a mutex via Grt")]
    GrtError(GrtError),
    #[error("the snapshot is locked")]
    SnapshotLocked,
    #[error("the expected size of the buffer did not match the actual size")]
    SizeMismatch,
}

const TELEMETRY_MTX_KEY: &str = "SCIL_LOGGING";
const SNAPSHOT_TELEMETRY_MTX_KEY: &str = "SCIL_LOGGING_SNP";

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

        SnapshottedTelemetryLog::new()?;

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

        // SAFETY: Could this MOVE the memory under the mutex? That would lead to UB / BSOD.. however, I do not think
        // this is actually creating a new pool allocation so, should be ok if its just emptying the actual Vec.
        let drained = take(&mut *lock);

        Ok(drained)
    }

    pub fn is_empty() -> Result<bool, TelemetryError> {
        let h_mtx = match Grt::get_fast_mutex::<Vec<TelemetryEntry>>(TELEMETRY_MTX_KEY) {
            Ok(m) => m,
            Err(e) => {
                return Err(TelemetryError::GrtError(e));
            }
        };

        let Ok(lock) = h_mtx.lock() else {
            let irql = unsafe { KeGetCurrentIrql() };
            return Err(TelemetryError::FastMtxFail(format!(
                "Failed to lock mutex. IRQL is: {irql}"
            )));
        };

        Ok(lock.is_empty())
    }
}

/// Creates a snapshot of the active telemetry log; this will self lock in that you cannot re-snapshot until
/// this snapshot has been drained. Failing to drain it after snapshotting will result in a perma-locked state.
pub struct SnapshottedTelemetryLog;

#[derive(Default)]
struct SnapshottedTelemetryLogInner {
    is_snapshotted: AtomicBool,
    data: Vec<TelemetryEntry>,
}

impl SnapshottedTelemetryLog {
    pub fn new() -> Result<(), TelemetryError> {
        if let Err(e) = Grt::register_fast_mutex_checked(
            SNAPSHOT_TELEMETRY_MTX_KEY,
            SnapshottedTelemetryLogInner {
                is_snapshotted: AtomicBool::new(false),
                data: Vec::new(),
            },
        ) {
            return Err(TelemetryError::GrtError(e));
        }

        Ok(())
    }

    /// Takes a snapshot of the active queue, on success returning the number of elements. The snapshot is
    /// then held in memory until such a time as it is drained.
    pub fn take_snapshot() -> Result<usize, TelemetryError> {
        let h_mtx =
            match Grt::get_fast_mutex::<SnapshottedTelemetryLogInner>(SNAPSHOT_TELEMETRY_MTX_KEY) {
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

        // If there is nothing present, just return a len of 0
        if TelemetryCache::is_empty()? {
            return Ok(0);
        }

        // SAFETY: We cannot race here as we are holding the outer lock via wdk_mutex::Grt
        if lock.is_snapshotted.load(Ordering::SeqCst) == true {
            return Err(TelemetryError::SnapshotLocked);
        }

        //
        // At this point we know we have data in the TelemetryLog, so we need to drain it, stick it in the
        // Snapshot, and mark as has a snapshot so we do not overwrite / mess up the held data.
        //
        let drained = TelemetryCache::drain()?;
        lock.is_snapshotted.store(true, Ordering::SeqCst);
        lock.data = drained;

        // We need to return the num elements for the calling IOCTL to use to create the buffer
        Ok(lock.data.len())
    }

    pub fn drain_snapshot(
        expected_size: usize,
    ) -> Result<Option<Vec<TelemetryEntry>>, TelemetryError> {
        let h_mtx =
            match Grt::get_fast_mutex::<SnapshottedTelemetryLogInner>(SNAPSHOT_TELEMETRY_MTX_KEY) {
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

        // If we aren't snapshotted then we have nothing pending, so return None
        if lock.is_snapshotted.load(Ordering::SeqCst) == false {
            return Ok(None);
        }

        // We don't want to proceed if we have bad state
        if expected_size != lock.data.len() {
            return Err(TelemetryError::SizeMismatch);
        }

        // Doing a mem take will reset the is_snapshotted flag from #[default]
        let drained = take(&mut *lock);

        Ok(Some(drained.data))
    }
}
