use crate::buf::fixed::{handle::CheckedOutBuf, FixedBuffers};
use crate::buf::IoBufMut;

use libc::{iovec, UIO_MAXIOV};
use log::{info, warn};
use tokio::sync::Notify;

use std::cmp;
use std::collections::HashMap;
use std::mem;
use std::ptr;
use std::slice;
use std::sync::Arc;

// Internal state shared by FixedBufPool and FixedBuf handles.
pub(crate) struct Pool<T: IoBufMut> {
    // Pointer to an allocated array of iovec records referencing
    // the allocated buffers. The number of initialized records is the
    // same as the length of the states array.
    raw_bufs: ptr::NonNull<iovec>,
    // Original capacity of raw_bufs as a Vec.
    orig_cap: usize,
    // State information on the buffers. Indices in this array correspond to
    // the indices in the array at raw_bufs.
    states: Vec<BufState>,
    // Table of head indices of the free buffer lists in each size bucket.
    free_buf_head_by_cap: HashMap<usize, u16>,
    // Original buffers, kept until drop
    buffers: Vec<T>,
    // Used to notify tasks pending on `next`
    notify_next_by_cap: HashMap<usize, Arc<Notify>>,

    state_change_mutex: std::sync::Mutex<i32>,
}

// State information of a buffer in the registry,
enum BufState {
    // The buffer is not in use.
    Free {
        // This field records the length of the initialized part.
        init_len: usize,
        // Index of the next buffer of the same capacity in a free buffer list, if any.
        next: Option<u16>,
    },
    // The buffer is checked out.
    // Its data are logically owned by the FixedBuf handle,
    // which also keeps track of the length of the initialized part.
    CheckedOut,
}

impl<T: IoBufMut> Pool<T> {
    pub(crate) fn new(bufs: impl Iterator<Item = T>) -> Self {
        // Limit the number of buffers to the maximum allowable number.
        let bufs = bufs.take(cmp::min(UIO_MAXIOV as usize, u16::MAX as usize));
        // Collect into `buffers`, which holds the backing buffers for
        // the lifetime of the pool. Using collect may allow
        // the compiler to apply collect in place specialization,
        // to avoid an allocation.
        let mut buffers = bufs.collect::<Vec<T>>();
        let mut iovecs = Vec::with_capacity(buffers.len());
        let mut states = Vec::with_capacity(buffers.len());
        let mut free_buf_head_by_cap = HashMap::new();
        for (index, buf) in buffers.iter_mut().enumerate() {
            let cap = buf.bytes_total();

            // Link the buffer as the head of the free list for its capacity.
            // This constructs the free buffer list to be initially retrieved
            // back to front, which should be of no difference to the user.
            let next = free_buf_head_by_cap.insert(cap, index as u16);

            iovecs.push(iovec {
                iov_base: buf.stable_mut_ptr() as *mut _,
                iov_len: cap,
            });
            states.push(BufState::Free {
                init_len: buf.bytes_init(),
                next,
            });
        }
        debug_assert_eq!(iovecs.len(), states.len());
        debug_assert_eq!(iovecs.len(), buffers.len());

        // Safety: Vec::as_mut_ptr never returns null
        let raw_bufs = unsafe { ptr::NonNull::new_unchecked(iovecs.as_mut_ptr()) };
        let orig_cap = iovecs.capacity();
        mem::forget(iovecs);
        Pool {
            raw_bufs,
            orig_cap,
            states,
            free_buf_head_by_cap,
            buffers,
            notify_next_by_cap: HashMap::new(),
            state_change_mutex: std::sync::Mutex::new(0),
        }
    }

    // If the free buffer list for this capacity is not empty, checks out the first buffer
    // from the list and returns its data. Otherwise, returns None.
    pub(crate) fn try_next(&mut self, cap: usize) -> Option<CheckedOutBuf> {
        let _ = self.state_change_mutex.lock();

        let free_head = self.free_buf_head_by_cap.get_mut(&cap)?;

        /*{
            Some(_free_head) => _free_head,
            None => {
                warn!("try_next - No entry found in hashmap for this capacity");

                let mut _free_head = None;

                for (index, state) in self.states.iter().enumerate() {
                    match state {
                        BufState::CheckedOut => {}
                        BufState::Free { init_len, next } => {
                            info!(
                                "Found free buffer at index {} - init_len = {}, next = {:?}",
                                index, init_len, next
                            );
                            self.free_buf_head_by_cap.insert(cap, index as u16);

                            _free_head = self.free_buf_head_by_cap.get_mut(&cap);
                        }
                    }
                }

                if let Some(__free_head) = _free_head {
                    __free_head
                } else {
                    warn!("try_next - All buffers in pool checked out.");
                    return None;
                }
            }
        };*/

        let index = *free_head as usize;
        let state = &mut self.states[index];

        let (init_len, next) = match *state {
            BufState::Free { init_len, next } => {
                *state = BufState::CheckedOut;
                (init_len, next)
            }
            BufState::CheckedOut => panic!("buffer at index {} is checked out", index),
        };

        // Update the head of the free list for this capacity.
        match next {
            Some(i) => {
                *free_head = i;
            }
            None => {
                self.free_buf_head_by_cap.remove(&cap);
            }
        }

        // Safety: the allocated array under the pointer is valid
        // for the lifetime of self, a free buffer index is inside the array,
        // as also asserted by the indexing operation on the states array
        // that has the same length.
        let iovec = unsafe { self.raw_bufs.as_ptr().add(index).read() };
        debug_assert_eq!(iovec.iov_len, cap);
        Some(CheckedOutBuf {
            iovec,
            init_len,
            index: index as u16,
        })
    }

    // Returns a `Notify` to use for waking up tasks awaiting a buffer of
    // the specified capacity.
    pub(crate) fn notify_on_next(&mut self, cap: usize) -> Arc<Notify> {
        let notify = self.notify_next_by_cap.entry(cap).or_default();
        Arc::clone(notify)
    }

    fn check_in_internal(&mut self, index: u16, init_len: usize) {
        let cap = self.iovecs()[index as usize].iov_len;
        let state = &mut self.states[index as usize];
        debug_assert!(
            matches!(state, BufState::CheckedOut),
            "the buffer must be checked out"
        );

        let _ = self.state_change_mutex.lock();

        //info!("check_in_internal - Reached check_in_internal()");

        // Link the buffer as the new head of the free list for its capacity.
        // Recently checked in buffers will be first to be reused,
        // improving cache locality.
        let next = self.free_buf_head_by_cap.insert(cap, index);

        *state = BufState::Free { init_len, next };

        // What if we have
        if let Some(notify) = self.notify_next_by_cap.get(&cap) {
            // Wake up a single task pending on `next`
            notify.notify_one();
        }
    }

    pub fn force_buffer_checkin(&mut self) {
        let length = self.states.len();

        for index in 0..length {
            self.check_in_internal(index as u16, 0);
        }
    }

    pub fn check_buffer_states(&mut self) {
        let _ = self.state_change_mutex.lock();

        info!(
            "check_buffer_states - self.states.len() = {}",
            self.states.len()
        );

        for (index, state) in self.states.iter().enumerate() {
            match state {
                BufState::CheckedOut => {
                    info!(
                        "check_buffer_states - Status of buffer {}: checked out",
                        index
                    );
                }
                BufState::Free { init_len, next } => {
                    info!(
                        "check_buffer_states - Status of buffer {}: free - init_len = {}, next = {:?}",
                        index, init_len, next
                    );
                }
            }
        }
    }
}

impl<T: IoBufMut> FixedBuffers for Pool<T> {
    fn iovecs(&self) -> &[iovec] {
        // Safety: the raw_bufs pointer is valid for the lifetime of self,
        // the length of the states array is also the length of buffers array
        // by construction.
        unsafe { slice::from_raw_parts(self.raw_bufs.as_ptr(), self.states.len()) }
    }

    unsafe fn check_in(&mut self, index: u16, init_len: usize) {
        //info!("check_in - Reached check_in() in pool.rs");

        self.check_in_internal(index, init_len)
    }
}

impl<T: IoBufMut> Drop for Pool<T> {
    fn drop(&mut self) {
        for (i, state) in self.states.iter().enumerate() {
            match state {
                BufState::Free { init_len, .. } => {
                    // Update buffer initialization.
                    // The buffer is about to dropped, but this may release it
                    // from Registry ownership, rather than deallocate.
                    unsafe { self.buffers[i].set_init(*init_len) };
                }
                BufState::CheckedOut => unreachable!("all buffers must be checked in"),
            }
        }

        // Rebuild Vec<iovec>, so it's dropped
        let _ = unsafe {
            Vec::from_raw_parts(self.raw_bufs.as_ptr(), self.states.len(), self.orig_cap)
        };
    }
}
