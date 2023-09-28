use crate::io::SharedFd;
use crate::runtime::driver::op;
use crate::runtime::driver::op::{Completable, Op};
use crate::runtime::CONTEXT;
use std::{boxed::Box, io};

pub(crate) struct Cancel {
    fd: SharedFd,
}

impl Op<Cancel> {
    pub(crate) fn cancel_fd(fd: &SharedFd) -> io::Result<Op<Cancel>> {
        use io_uring::{opcode, types};

        CONTEXT.with(|x| {
            x.handle().expect("Not in a runtime context").submit_op(
                Cancel {
                    fd: fd.clone()
                },
                |cancel| {
                    opcode::AsyncCancel::new(
                        cancel.fd.raw_fd() as _
                    )
                    .flags(types::AsyncCancelFlags::FD | types::AsyncCancelFlags::ALL)
                    .build()
                },
            )
        })
    }
}

impl Completable for Cancel {
    type Output = io::Result<()>;

    fn complete(self, cqe: op::CqeResult) -> Self::Output {
        cqe.result.map(|_| ())
    }
}
