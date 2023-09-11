use crate::{
    buf::fixed::FixedBuf,
    buf::{BoundedBuf, BoundedBufMut},
    io::{SharedFd, Socket},
    UnsubmittedWrite,
};

use std::os::raw::c_char;

//use libxdp_sys::{_xsk_ring_cons__peek, _xsk_ring_cons__release, _xsk_ring_cons__rx_desc};

const XSK_RING_CONS__DEFAULT_NUM_DESCS: u32 = 2048;
const XSK_RING_PROD__DEFAULT_NUM_DESCS: u32 = 2048;

const XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: u32 = (1 << 0);
const XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD: u32 = (1 << 0);

pub struct xsk_socket {}

struct xsk_umem {}

pub struct xsk_ring_prod {}

pub struct xsk_ring_cons {}

union xsk_socket_config_union {
    libbpf_flags: u32,
    libxdp_flags: u32,
}

pub struct xsk_socket_config {
    pub rx_size: u32,
    pub tx_size: u32,
    pub lib_flags: xsk_socket_config_union,
    pub xdp_flags: u32,
    pub bind_flags: u16,
}

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
    ) -> i32 {
        // Check that we have the necessary valid pointers.
        if !umem || !xsk_ptr || !(rx || tx) {
            return libc::EFAULT;
        }

        // Calloc size of xsk socket struct
        let mut xsk = Box::new();

        // Set xdp_socket_config
        set_socket_config()

        // Check if umem refcount
    }

    pub fn set_socket_config(
        cfg: &mut xsk_socket_config,
        usr_cfg: *const cxsk_socket_config,
    ) -> i32 {
        if (!usr_cfg) {
            cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
            cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
            cfg.libbpf_flags = 0;
            cfg.xdp_flags = 0;
            cfg.bind_flags = 0;
        }

        if (usr_cfg.libbpf_flags & !XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD) {
            return libc::EINVAL;
        }

        cfg.rx_size = *usr_cfg.rx_size;
        cfg.tx_size = *usr_cfg.tx_size;
        cfg.libbpf_flags = *usr_cfg.libbpf_flags;
        cfg.xdp_flags = *usr_cfg.xdp_flags;
        cfg.bind_flags = *usr_cfg.bind_flags;
    }

    pub async fn sendmsg() {
        //libxdp_sys::sendmsg;
    }

    pub async fn recvmsg() {}
}
