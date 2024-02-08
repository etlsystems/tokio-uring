use crate::io::SharedFd;
use crate::runtime::driver::op::{Completable, CqeResult, Op};
use crate::runtime::CONTEXT;
use std::io;

pub(crate) struct UringCmd16<T> {
    /// Holds a strong ref to the FD, preventing the file from being closed
    /// while the operation is in-flight.
    #[allow(dead_code)]
    fd: SharedFd,
    // Holds any required metadata stable for the lifetime of the operation
    metadata: T,
}

impl<T> Op<UringCmd16<T>> {
    /// A file/device-specific 16-byte command, akin (but not equivalent) to ioctl
    pub(crate) fn uring_cmd16(
        fd: &SharedFd,
        cmd_op: u32,
        cmd: [u8; 16],
        buf_index: Option<u16>,
        metadata: T,
    ) -> io::Result<Op<UringCmd16<T>>> {
        use io_uring::{opcode, types};

        CONTEXT.with(|x| {
            x.handle().expect("Not in a runtime context").submit_op(
                UringCmd16 {
                    fd: fd.clone(),
                    metadata,
                },
                |_| {
                    opcode::UringCmd16::new(types::Fd(fd.raw_fd()), cmd_op)
                        .buf_index(buf_index)
                        .cmd(cmd)
                        .build()
                },
            )
        })
    }
}

impl<T> Completable for UringCmd16<T> {
    type Output = (std::result::Result<u32, io::Error>, T);

    fn complete(self, cqe: CqeResult) -> Self::Output {
        (cqe.result, self.metadata)
    }
}

#[cfg(feature = "sqe128")]
pub(crate) struct UringCmd80 {
    /// Holds a strong ref to the FD, preventing the file from being closed
    /// while the operation is in-flight.
    #[allow(dead_code)]
    fd: SharedFd,
}

#[cfg(feature = "sqe128")]
impl Op<UringCmd80> {
    /// A file/device-specific 80-byte command, akin (but not equivalent) to ioctl
    pub(crate) fn uring_cmd80(
        fd: &SharedFd,
        cmd_op: u32,
        cmd: [u8; 80],
    ) -> io::Result<Op<UringCmd80>> {
        use io_uring::{opcode, types};

        CONTEXT.with(|x| {
            x.handle().expect("Not in a runtime context").submit_op(
                UringCmd80 { fd: fd.clone() },
                |_| {
                    opcode::UringCmd80::new(types::Fd(fd.raw_fd()), cmd_op)
                        .cmd(cmd)
                        .build()
                },
            )
        })
    }
}

#[cfg(feature = "sqe128")]
impl Completable for UringCmd80 {
    type Output = io::Result<u32>;

    fn complete(self, cqe: CqeResult) -> Self::Output {
        cqe.result
    }
}
