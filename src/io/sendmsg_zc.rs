use crate::buf::BoundedBuf;
use crate::io::SharedFd;
use crate::runtime::driver::op::{Completable, CqeResult, MultiCQEFuture, Op, Updateable};
use crate::runtime::CONTEXT;
use socket2::SockAddr;
use std::io;
use std::io::IoSlice;
use std::net::SocketAddr;

pub(crate) struct SendMsgZc<T, U> {
    #[allow(dead_code)]
    fd: SharedFd,
    #[allow(dead_code)]
    io_bufs: Vec<T>,
    #[allow(dead_code)]
    io_slices: Vec<IoSlice<'static>>,
    #[allow(dead_code)]
    socket_addr: Option<Box<SockAddr>>,
    msg_control: Option<U>,
    msghdr: libc::msghdr,

    /// Hold the result of number of transmitted bytes or socket error
    result: Result<usize, io::Error>
}

impl<T: BoundedBuf, U: BoundedBuf> Op<SendMsgZc<T, U>, MultiCQEFuture> {
    pub(crate) fn sendmsg_zc(
        fd: &SharedFd,
        io_bufs: Vec<T>,
        socket_addr: Option<SocketAddr>,
        msg_control: Option<U>,
    ) -> io::Result<Self> {
        use io_uring::{opcode, types};

        let mut msghdr: libc::msghdr = unsafe { std::mem::zeroed() };

        let mut io_slices: Vec<IoSlice<'static>> = Vec::with_capacity(io_bufs.len());

        for io_buf in &io_bufs {
            io_slices.push(IoSlice::new(unsafe {
                std::slice::from_raw_parts(io_buf.stable_ptr(), io_buf.bytes_init())
            }))
        }

        msghdr.msg_iov = io_slices.as_ptr() as *mut _;
        msghdr.msg_iovlen = io_slices.len() as _;

        let socket_addr = socket_addr.map(|_socket_addr| {
            let socket_addr = Box::new(SockAddr::from(_socket_addr));
            msghdr.msg_name = socket_addr.as_ptr() as *const _ as *mut _;
            msghdr.msg_namelen = socket_addr.len();
            socket_addr
        });

        msg_control.as_ref().map(|_msg_control| {
            msghdr.msg_control = _msg_control.stable_ptr() as *mut _;
            msghdr.msg_controllen = _msg_control.bytes_init();
        });

        CONTEXT.with(|x| {
            assert!(msghdr.msg_iovlen > 0);
            assert_eq!(msghdr.msg_iov, io_slices.as_ptr() as *const _ as *mut _);
            assert!(io_slices.len() > 0);
            assert!(io_slices[0].len() > 0);
            x.handle().expect("Not in a runtime context").submit_op(
                SendMsgZc {
                    fd: fd.clone(),
                    io_bufs,
                    socket_addr,
                    io_slices,
                    msg_control,
                    msghdr,
                    result: Ok(0)
                },
                |sendmsg_zc| {
                    opcode::SendMsgZc::new(
                        types::Fd(sendmsg_zc.fd.raw_fd()),
                        &sendmsg_zc.msghdr as *const _,
                        1 // .flags(io_uring::sys::IORING_RECVSEND_POLL_FIRST)
                    )
                    .build()
                },
            )
        })
    }
}

impl<T, U> Completable for SendMsgZc<T, U> {
    type Output = (io::Result<usize>, Vec<T>, Option<U>);

    fn complete(mut self, cqe: CqeResult) -> (io::Result<usize>, Vec<T>, Option<U>) {
        self.update(cqe);

        // Recover the data buffers.
        let io_bufs = self.io_bufs;

        // Recover the ancillary data buffer.
        let msg_control = self.msg_control;

        (self.result, io_bufs, msg_control)
    }
}

impl<T,U> Updateable for SendMsgZc<T, U>{
    /// Update increments the number of bytes observed
    /// If an error is observed, this will persist
    fn update(&mut self, cqe: CqeResult) {
        if let Ok(a) = self.result {
            self.result = cqe.result.map(|n| a + n as usize)
        }
    }
}
