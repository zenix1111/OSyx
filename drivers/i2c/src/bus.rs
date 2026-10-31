//! What the platform provides to the drivers, and what the drivers offer.

/// 32-bit register access to a device's memory-mapped registers.
pub trait Mmio {
    fn read32(&self, offset: usize) -> u32;
    fn write32(&mut self, offset: usize, value: u32);
}

/// Time for bounded waits. All times are microseconds from any fixed
/// point; a clock that stops counting would make a wait unbounded, so
/// implementations must advance.
pub trait Clock {
    fn now_us(&self) -> u64;
    /// Called between two looks at a register: spin hint or yield.
    fn relax(&self);
    /// Sleeps at least `ms` milliseconds (the caller may be descheduled).
    fn sleep_ms(&self, ms: u32);
}

/// Why a transfer failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum I2cError {
    /// The target did not acknowledge its address or a data byte.
    Nack,
    /// Another master won the bus.
    ArbitrationLost,
    /// The transfer did not finish in time (stuck bus, clock stretching).
    Timeout,
    /// The controller reported another abort (`IC_TX_ABRT_SOURCE`).
    Abort(u32),
    /// Empty transfer, or longer than [`MAX_TRANSFER`].
    InvalidLength,
    /// The controller could not be disabled or enabled.
    Controller,
}

/// Longest write or read of one transfer.
pub const MAX_TRANSFER: usize = 8192;

/// A 7-bit-addressed I2C master.
pub trait I2cBus {
    /// One transaction: `write` (if not empty), then, after a repeated
    /// start, `read` (if not empty), then stop. At least one of them must
    /// be non-empty.
    fn transfer(&mut self, address: u8, write: &[u8], read: &mut [u8]) -> Result<(), I2cError>;
}

/// Waits until `done()` is true; false if `timeout_us` pass first.
pub fn wait_until(clock: &dyn Clock, timeout_us: u64, mut done: impl FnMut() -> bool) -> bool {
    let start = clock.now_us();
    loop {
        if done() {
            return true;
        }
        if clock.now_us().saturating_sub(start) >= timeout_us {
            // One last look: the check above may have been slow.
            return done();
        }
        clock.relax();
    }
}
