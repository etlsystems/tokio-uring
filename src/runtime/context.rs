use crate::runtime::driver;
use crate::runtime::driver::{Handle, WeakHandle};
use io_uring::{cqueue, squeue};
use std::cell::RefCell;

/// Owns the driver and resides in thread-local storage.
pub(crate) struct RuntimeContext<S: squeue::EntryMarker, C: cqueue::EntryMarker> {
    driver: RefCell<Option<driver::Handle<S, C>>>,
}

impl<S, C> RuntimeContext<S, C> {
    /// Construct the context with an uninitialized driver.
    pub(crate) const fn new() -> Self {
        Self {
            driver: RefCell::new(None),
        }
    }

    /// Initialize the driver.
    pub(crate) fn set_handle(&self, handle: Handle<S, C>) {
        let mut guard = self.driver.borrow_mut();

        assert!(guard.is_none(), "Attempted to initialize the driver twice");

        *guard = Some(handle);
    }

    pub(crate) fn unset_driver(&self) {
        let mut guard = self.driver.borrow_mut();

        assert!(guard.is_some(), "Attempted to clear nonexistent driver");

        *guard = None;
    }

    /// Check if driver is initialized
    #[allow(dead_code)]
    pub(crate) fn is_set(&self) -> bool {
        self.driver
            .try_borrow()
            .map(|b| b.is_some())
            .unwrap_or(false)
    }

    pub(crate) fn handle(&self) -> Option<Handle<S, C>> {
        self.driver.borrow().clone()
    }

    #[allow(dead_code)]
    pub(crate) fn weak(&self) -> Option<WeakHandle<S, C>> {
        self.driver.borrow().as_ref().map(Into::into)
    }
}
