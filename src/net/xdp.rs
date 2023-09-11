use crate::{
    buf::fixed::FixedBuf,
    buf::{BoundedBuf, BoundedBufMut},
    io::{SharedFd, Socket},
    UnsubmittedWrite,
};

use std::os::raw::c_char;

//use libxdp_sys::{_xsk_ring_cons__peek, _xsk_ring_cons__release, _xsk_ring_cons__rx_desc};

pub struct xsk_socket {}

struct xsk_umem {}

pub struct xsk_ring_prod {}

pub struct xsk_ring_cons {}

pub struct xsk_socket_config {}

pub struct XdpSocket {
    pub(super) inner: Socket,
}

impl XdpSocket {
    // Must already have umem
    pub fn create(
        xsk_ptr: *mut *mut xsk_socket,
        ifname: *const c_char,
        queue_id: u32,
        umem: *mut xsk_umem,
        rx: *mut xsk_ring_cons,
        tx: *mut xsk_ring_prod,
        fill: *mut xsk_ring_prod,
        comp: *mut xsk_ring_cons,
        usr_config: *const xsk_socket_config,
    ) {
        // Calloc size of xsk socket struct

        // Set xdp_socket_config

        // Check if umem refcount
    }

    pub async fn sendmsg() {
        //libxdp_sys::sendmsg;
    }

    pub async fn recvmsg() {}
}
