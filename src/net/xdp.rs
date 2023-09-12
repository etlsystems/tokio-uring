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

const XSK_UMEM__DEFAULT_FRAME_SHIFT: u32 = 12; /* 4096 bytes */
const XSK_UMEM__DEFAULT_FRAME_SIZE: u32 = (1 << XSK_UMEM__DEFAULT_FRAME_SHIFT);
const XSK_UMEM__DEFAULT_FRAME_HEADROOM: u32 = 0;
const XSK_UMEM__DEFAULT_FLAGS: u32 = 0;

const XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: u32 = (1 << 0);
const XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD: u32 = (1 << 0);

const AF_XDP: u32 = 44;
const PF_XDP: u32 = 44;

const SO_NETNS_COOKIE: u32 = 71;

const SOCK_RAW: u32 = 3;

const SOL_SOCKET: u32 = 1;

pub struct xsk_ctx {
    fill: *mut xsk_ring_prod,
    comp: *mut xsk_ring_cons,
    umem: *mut xsk_umem,
    queue_id: u32,
    refcount: i32,
    ifindex: i32,
    netns_cookie: u64,
    xsks_map_fs: i32,
    // list,
    // xdp_prog,
    refcnt_map_fd: i32,
    //ifname,
}

//#[derive(Default)]
pub struct xsk_socket {
    rx: *mut xsk_ring_cons,
    tx: *mut xsk_ring_prod,
    ctx: *mut xsk_ctx,
    config: xsk_socket_config,
    fd: i32,
}

pub struct xsk_umem {
    pub fill_save: *mut xsk_ring_prod,
    pub comp_save: *mut xsk_ring_cons,
    //umem_area
    pub config: xsk_umem_config,
    pub fd: i32,
    pub refcount: i32,
    //ctx_list
    pub rx_ring_setup_done: bool,
    pub tx_ring_setup_done: bool,
}

pub struct xsk_ring_prod {
    cached_prod: u32,
    cached_cons: u32,
    mask: u32,
    size: u32,
    producer: *mut u32,
    consumer: *mut u32,
    ring: *mut std::ffi::c_void,
    flags: *mut u32,
}

pub struct xsk_ring_cons {
    cached_prod: u32,
    cached_cons: u32,
    mask: u32,
    size: u32,
    producer: *mut u32,
    consumer: *mut u32,
    ring: *mut std::ffi::c_void,
    flags: *mut u32,
}

pub struct xsk_umem_config {
    pub fill_size: u32,
    pub comp_size: u32,
    pub frame_size: u32,
    pub frame_headroom: u32,
    pub flags: u32,
}

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

pub struct XdpUmem {}

impl XdpUmem {
    pub fn create() {}

    pub fn set_umem_config(cfg: &mut xsk_umem_config, usr_cfg: &Option<xsk_umem_config>) {
        match *usr_cfg {
            Some(_usr_cfg) => {
                cfg.fill_size = _usr_cfg.fill_size;
                cfg.comp_size = _usr_cfg.comp_size;
                cfg.frame_size = _usr_cfg.frame_size;
                cfg.frame_headroom = _usr_cfg.frame_headroom;
                cfg.flags = _usr_cfg.flags;
            }

            None => {
                cfg.fill_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
                cfg.comp_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
                cfg.frame_size = XSK_UMEM__DEFAULT_FRAME_SIZE;
                cfg.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM;
                cfg.flags = XSK_UMEM__DEFAULT_FLAGS;
            }
        }
    }
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
        umem: &mut xsk_umem,
        rx: *mut xsk_ring_cons,
        tx: *mut xsk_ring_prod,
        fill: *mut xsk_ring_prod,
        comp: *mut xsk_ring_cons,
        usr_config: &Option<xsk_socket_config>,
    ) -> i32 {
        let mut rx_setup_done: bool = false;
        let mut tx_setup_done: bool = false;
        let mut err: i32 = 0;
        let mut ifindex: i32 = 0;
        let mut netns_cookie: u64 = 0;
        let mut optlen: u32 = 0;

        // Check that we have the necessary valid pointers.
        if !umem || xsk_ptr.is_null() || (rx.is_null() && tx.is_null()) {
            return libc::EFAULT;
        }

        // Calloc size of xsk socket struct
        let mut xsk: Box<xsk_socket> = Default::default();

        // Set xdp_socket_config
        err = XdpSocket::set_socket_config(&mut xsk.config, usr_config);

        if err != 0 {
            // goto out_xsk_alloc;
        }

        // Get interface index from name
        unsafe {
            ifindex = libc::if_nametoindex(ifname as *mut i8) as i32;
        }

        if ifindex == 0 {
            err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();
            // goto out_xsk_alloc;
        }

        // Check if umem refcount is greater than zero.
        if ((*umem).refcount > 0) {
            unsafe {
                xsk.fd = libc::socket(AF_XDP as i32, SOCK_RAW as i32, 0);
            }

            if xsk.fd < 0 {}
        } else {
            xsk.fd = (*umem).fd;
            rx_setup_done = (*umem).rx_ring_setup_done;
            tx_setup_done = (*umem).tx_ring_setup_done;
        }

        (*umem).refcount += 1;

        optlen = std::mem::size_of::<u64>() as u32;

        unsafe {
            err = libc::getsockopt(
                xsk.fd,
                SOL_SOCKET as i32,
                SO_NETNS_COOKIE as i32,
                &mut netns_cookie as *mut u64 as *mut std::ffi::c_void,
                &mut optlen as *mut u32,
            );
        }

        if err != 0 {
            if std::io::Error::last_os_error().raw_os_error().unwrap() != libc::ENOPROTOOPT {
                err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();
            }
        }

        // get ctx

        // Setup rx if required

        // Setup tx if required

        // Get mmap offsets

        // rx mmap

        // tx mmap

        return 0;
    }

    pub fn set_socket_config(
        cfg: &mut xsk_socket_config,
        usr_cfg: &Option<xsk_socket_config>,
    ) -> i32 {
        match *usr_cfg {
            Some(_usr_cfg) => {
                if (_usr_cfg.lib_flags.libbpf_flags & !(XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD)) != 0 {
                    return libc::EINVAL;
                }

                cfg.rx_size = _usr_cfg.rx_size;
                cfg.tx_size = _usr_cfg.tx_size;
                cfg.lib_flags.libbpf_flags = _usr_cfg.lib_flags.libbpf_flags;
                cfg.xdp_flags = _usr_cfg.xdp_flags;
                cfg.bind_flags = _usr_cfg.bind_flags;
            }

            None => {
                cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
                cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
                cfg.lib_flags.libbpf_flags = 0;
                cfg.xdp_flags = 0;
                cfg.bind_flags = 0;
            }
        }

        0
    }

    pub async fn sendmsg() {
        //libxdp_sys::sendmsg;
    }

    pub async fn recvmsg() {}
}
