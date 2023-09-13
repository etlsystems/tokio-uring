use libc::{sockaddr, MAP_FAILED, MAP_POPULATE, MAP_SHARED, PROT_READ, PROT_WRITE, SOL_XDP};

use crate::{
    buf::fixed::FixedBuf,
    buf::{BoundedBuf, BoundedBufMut},
    io::{SharedFd, Socket},
    UnsubmittedWrite,
};

use std::{borrow::BorrowMut, f64::consts, os::raw::c_char};

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

const INIT_NS: u32 = 1;

const XDP_MMAP_OFFSETS: u32 = 1;
const XDP_RX_RING: u32 = 2;
const XDP_TX_RING: u32 = 3;
const XDP_UMEM_REG: u32 = 4;
const XDP_UMEM_FILL_RING: u32 = 5;
const XDP_UMEM_COMPLETION_RING: u32 = 6;
const XDP_STATISTICS: u32 = 7;
const XDP_OPTIONS: u32 = 8;

const XDP_PGOFF_RX_RING: u32 = 0;
const XDP_PGOFF_TX_RING: u32 = 0x80000000;
const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x100000000;
const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x180000000;

const XDP_SHARED_UMEM: u32 = (1 << 0);

#[derive(Clone)]
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
    ifname: String,
}

impl Default for xsk_ctx {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

//#[derive(Default)]
pub struct xsk_socket {
    rx: *mut xsk_ring_cons,
    tx: *mut xsk_ring_prod,
    ctx: *mut xsk_ctx,
    config: xsk_socket_config,
    fd: i32,
}

impl Default for xsk_socket {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

pub struct xsk_socket_config {
    pub rx_size: u32,
    pub tx_size: u32,
    pub libbpf_flags: u32,
    pub xdp_flags: u32,
    pub bind_flags: u16,
}

pub struct xsk_umem {
    pub fill_save: *mut xsk_ring_prod,
    pub comp_save: *mut xsk_ring_cons,
    pub umem_area: *mut std::ffi::c_void,
    pub config: xsk_umem_config,
    pub fd: i32,
    pub refcount: i32,
    pub ctx_list: std::collections::LinkedList<Box<xsk_ctx>>,
    pub rx_ring_setup_done: bool,
    pub tx_ring_setup_done: bool,
}

impl Default for xsk_umem {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

pub struct xsk_umem_config {
    pub fill_size: u32,
    pub comp_size: u32,
    pub frame_size: u32,
    pub frame_headroom: u32,
    pub flags: u32,
}

pub struct xsk_umem_reg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

impl Default for xsk_umem_reg {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
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

pub struct xdp_ring_offset {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

pub struct xdp_mmap_offsets {
    pub rx: xdp_ring_offset,
    pub tx: xdp_ring_offset,
    pub fr: xdp_ring_offset,
    pub cr: xdp_ring_offset,
}

impl Default for xdp_mmap_offsets {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

struct xdp_desc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

pub struct sockaddr_xdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}

impl Default for sockaddr_xdp {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

pub fn xsk_page_aligned(buffer: *mut std::ffi::c_void) -> bool {
    let addr: u64 = buffer as u64;

    (addr & 4095) != 0
}

pub fn xsk_create_umem_rings(
    umem: &mut xsk_umem,
    fd: i32,
    fill: *mut xsk_ring_prod,
    comp: *mut xsk_ring_cons,
) -> i32 {
    let mut off: xdp_mmap_offsets = Default::default();
    let mut map: *mut std::ffi::c_void = std::ptr::null_mut();
    let mut err = 0;

    unsafe {
        err = libc::setsockopt(
            fd,
            SOL_XDP,
            XDP_UMEM_FILL_RING as i32,
            &umem.config.fill_size as *const u32 as *const std::ffi::c_void,
            std::mem::size_of_val(&umem.config.fill_size) as u32,
        );
    }

    if err != 0 {
        return -std::io::Error::last_os_error().raw_os_error().unwrap();
    }

    unsafe {
        err = libc::setsockopt(
            fd,
            SOL_XDP,
            XDP_UMEM_COMPLETION_RING as i32,
            &umem.config.comp_size as *const u32 as *const std::ffi::c_void,
            std::mem::size_of_val(&umem.config.comp_size) as u32,
        );
    }

    if err != 0 {
        return -std::io::Error::last_os_error().raw_os_error().unwrap();
    }

    err = xsk_get_mmap_offsets(fd, &mut off);

    if err != 0 {
        return -std::io::Error::last_os_error().raw_os_error().unwrap();
    }

    unsafe {
        map = libc::mmap(
            std::ptr::null_mut(),
            (off.fr.desc as usize) + (umem.config.fill_size as usize) * std::mem::size_of::<u64>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            XDP_UMEM_PGOFF_FILL_RING as i64,
        )
    }

    if map == libc::MAP_FAILED {
        err = -std::io::Error::last_os_error().raw_os_error().unwrap();

        unsafe {
            libc::munmap(
                map,
                (off.fr.desc as usize)
                    + (umem.config.fill_size as usize) * std::mem::size_of::<u64>(),
            );
        }

        return err;
    }

    unsafe {
        (*fill).mask = umem.config.fill_size - 1;
        (*fill).size = umem.config.fill_size;
        (*fill).producer = map.add(off.fr.producer as usize) as *mut u32;
        (*fill).consumer = map.add(off.fr.consumer as usize) as *mut u32;
        (*fill).flags = map.add(off.fr.flags as usize) as *mut u32;
        (*fill).ring = map.add(off.fr.desc as usize);
        (*fill).cached_cons = umem.config.fill_size;
    }

    unsafe {
        map = libc::mmap(
            std::ptr::null_mut(),
            (off.cr.desc as usize) + (umem.config.comp_size as usize) * std::mem::size_of::<u64>(),
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_POPULATE,
            fd,
            XDP_UMEM_PGOFF_COMPLETION_RING as i64,
        )
    }

    if map == libc::MAP_FAILED {
        err = -std::io::Error::last_os_error().raw_os_error().unwrap();

        unsafe {
            libc::munmap(
                map,
                (off.cr.desc as usize)
                    + (umem.config.comp_size as usize) * std::mem::size_of::<u64>(),
            );
        }

        return err;
    }

    unsafe {
        (*comp).mask = umem.config.comp_size - 1;
        (*comp).size = umem.config.comp_size;
        (*comp).producer = map.add(off.cr.producer as usize) as *mut u32;
        (*comp).consumer = map.add(off.cr.consumer as usize) as *mut u32;
        (*comp).flags = map.add(off.cr.flags as usize) as *mut u32;
        (*comp).ring = map.add(off.cr.desc as usize);
    }

    0
}

pub struct XdpUmem {}

impl XdpUmem {
    pub fn create(
        umem_ptr: *mut *mut xsk_umem,
        fd: i32,
        size: u64,
        umem_area: *mut std::ffi::c_void,
        fill: *mut xsk_ring_prod,
        comp: *mut xsk_ring_cons,
        usr_config: &Option<xsk_umem_config>,
    ) -> i32 {
        let mut mr: xsk_umem_reg = Default::default();
        let mut umem: Box<xsk_umem> = Default::default();
        let mut err = 0;

        if umem_area.is_null() || umem_ptr.is_null() || fill.is_null() || comp.is_null() {
            return -libc::EFAULT;
        }

        if (size == 0) && !(xsk_page_aligned(umem_area)) {
            return -libc::EINVAL;
        }

        if fd < 0 {
            unsafe {
                umem.fd = libc::socket(AF_XDP as i32, SOCK_RAW as i32, 0);
            }
        } else {
            umem.fd = fd;
        }

        if umem.fd < 0 {
            err = -std::io::Error::last_os_error().raw_os_error().unwrap();

            drop(umem);

            return err;
        }

        umem.umem_area = umem_area;

        XdpUmem::set_umem_config(&mut umem.config, usr_config);

        mr.addr = umem_area as u64;
        mr.len = size;
        mr.chunk_size = umem.config.frame_size;
        mr.headroom = umem.config.frame_headroom;
        mr.flags = umem.config.flags;

        unsafe {
            err = libc::setsockopt(
                umem.fd,
                SOL_XDP,
                XDP_UMEM_REG as i32,
                &mr as *const xsk_umem_reg as *const std::ffi::c_void,
                std::mem::size_of_val(&mr) as u32,
            )
        }

        if err != 0 {
            err = -std::io::Error::last_os_error().raw_os_error().unwrap();

            unsafe {
                libc::close(fd);
            }
            drop(umem);

            return err;
        }

        let fd_temp = umem.fd;

        err = xsk_create_umem_rings(&mut umem, fd_temp, fill, comp);

        if err != 0 {
            unsafe {
                libc::close(fd);
            }
            drop(umem);

            return err;
        }

        umem.fill_save = fill;
        umem.comp_save = comp;

        unsafe {
            (*umem_ptr) = umem.as_mut();
        }

        0
    }

    pub fn set_umem_config(cfg: &mut xsk_umem_config, usr_cfg: &Option<xsk_umem_config>) {
        match usr_cfg {
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

pub fn xsk_setup_xdp_program(xsk: &mut xsk_socket, xsks_map_fs: i32) -> i32 {
    0
}

pub fn xsk_get_mmap_offsets(fd: i32, off: &mut xdp_mmap_offsets) -> i32 {
    let mut err: i32 = 0;
    let mut optlen: u32 = 0;

    optlen = std::mem::size_of_val(off) as u32;

    unsafe {
        err = libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS as i32,
            off as *mut xdp_mmap_offsets as *mut std::ffi::c_void,
            &mut optlen,
        )
    }

    if err != 0 {
        return 0 - std::io::Error::last_os_error().raw_os_error().unwrap();
    }

    if optlen == std::mem::size_of_val(off) as u32 {
        return 0;
    }

    libc::EINVAL
}

pub fn xsk_get_ctx(
    umem: &mut xsk_umem,
    netns_cookie: u64,
    ifindex: i32,
    queue_id: u32,
) -> Option<Box<xsk_ctx>> {
    if umem.ctx_list.is_empty() {
        return None;
    }

    for ctx in &umem.ctx_list {
        if (ctx.netns_cookie == netns_cookie)
            && (ctx.ifindex == ifindex)
            && (ctx.queue_id == queue_id)
        {
            return Some(ctx.clone());
        }
    }

    None
}

pub fn xsk_create_ctx(
    xsk: &xsk_socket,
    umem: &mut xsk_umem,
    netns_cookie: u64,
    ifindex: i32,
    ifname: &String,
    queue_id: u32,
    fill: *mut xsk_ring_prod,
    comp: *mut xsk_ring_cons,
) -> Option<xsk_ctx> {
    let mut err: i32 = 0;
    let mut ctx: Box<xsk_ctx> = Default::default();

    if umem.fill_save.is_null() {
        err = xsk_create_umem_rings(umem, xsk.fd, fill, comp);

        if err != 0 {
            return None;
        }
    } else if (umem.fill_save != fill) || (umem.comp_save != comp) {
        // Copy data
    }

    ctx.netns_cookie = netns_cookie;
    ctx.ifindex = ifindex;
    ctx.refcount = 1;
    ctx.umem = umem;
    ctx.queue_id = queue_id;
    ctx.ifname = ifname.clone();
    ctx.fill = fill;
    ctx.comp = comp;

    umem.ctx_list.push_back(ctx.clone());

    Some(*ctx)
}

pub struct XdpSocket {
    pub(super) inner: Socket,
}

impl XdpSocket {
    // Must already have umem
    pub fn create(
        xsk_ptr: *mut *mut xsk_socket,
        ifname: &String,
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
        let mut off: xdp_mmap_offsets = Default::default();
        let mut rx_map: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut tx_map: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut sxdp: sockaddr_xdp = Default::default();

        // Check that we have the necessary valid pointers.
        if xsk_ptr.is_null() || (rx.is_null() && tx.is_null()) {
            return libc::EFAULT;
        }

        // Calloc size of xsk socket struct
        let mut xsk: xsk_socket = Default::default();

        // Set xdp_socket_config
        err = XdpSocket::set_socket_config(&mut xsk.config, usr_config);

        if err != 0 {
            // goto out_xsk_alloc;

            return err;
        }

        // Get interface index from name
        unsafe {
            ifindex = libc::if_nametoindex(ifname.as_bytes() as *const [u8] as *const i8) as i32;
        }

        if ifindex == 0 {
            err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();
            // goto out_xsk_alloc;

            return err;
        }

        // Check if umem refcount is greater than zero.
        if umem.refcount > 0 {
            unsafe {
                xsk.fd = libc::socket(AF_XDP as i32, SOCK_RAW as i32, 0);
            }

            if xsk.fd < 0 {
                err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();
                // goto out_xsk_alloc

                return err;
            }
        } else {
            xsk.fd = umem.fd;
            rx_setup_done = umem.rx_ring_setup_done;
            tx_setup_done = umem.tx_ring_setup_done;
        }

        umem.refcount += 1;

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

                //goto out_socket
                return err;
            }

            netns_cookie = INIT_NS as u64;
        }

        // get ctx
        let mut ctx = match xsk_get_ctx(umem, netns_cookie, ifindex, queue_id) {
            Some(_ctx) => *_ctx,
            None => {
                if fill.is_null() || comp.is_null() {
                    err = -libc::EFAULT;
                    // goto out_socket
                    return err;
                }

                let ctx = match xsk_create_ctx(
                    &xsk,
                    umem,
                    netns_cookie,
                    ifindex,
                    ifname,
                    queue_id,
                    fill,
                    comp,
                ) {
                    Some(_ctx) => _ctx,
                    None => {
                        //goto out_socket;
                        return libc::ENOMEM;
                    }
                };

                ctx
            }
        };

        xsk.ctx = &mut ctx;

        // Setup rx if required
        if !rx.is_null() && !rx_setup_done {
            unsafe {
                err = libc::setsockopt(
                    xsk.fd,
                    SOL_XDP,
                    XDP_RX_RING as i32,
                    &xsk.config.rx_size as *const u32 as *const std::ffi::c_void,
                    std::mem::size_of_val(&xsk.config.rx_size) as u32,
                );
            }

            if err != 0 {
                err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();
                // goto out_put_ctx

                return err;
            }

            if xsk.fd == umem.fd {
                umem.rx_ring_setup_done = true;
            }
        }

        // Setup tx if required
        if !tx.is_null() && !tx_setup_done {
            unsafe {
                err = libc::setsockopt(
                    xsk.fd,
                    SOL_XDP,
                    XDP_TX_RING as i32,
                    &xsk.config.tx_size as *const u32 as *const std::ffi::c_void,
                    std::mem::size_of_val(&xsk.config.tx_size) as u32,
                );
            }

            if err != 0 {
                err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();
                // goto out_put_ctx

                return err;
            }

            if xsk.fd == umem.fd {
                umem.tx_ring_setup_done = true;
            }
        }

        // Get mmap offsets
        err = xsk_get_mmap_offsets(xsk.fd, &mut off);

        if err != 0 {
            err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();
            // goto out_put_ctx;

            return err;
        }

        // rx mmap
        if !rx.is_null() {
            unsafe {
                rx_map = libc::mmap(
                    std::ptr::null_mut() as *mut std::ffi::c_void,
                    (off.rx.desc as usize)
                        + (xsk.config.rx_size as usize) * std::mem::size_of::<xdp_desc>(),
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_POPULATE,
                    xsk.fd,
                    XDP_PGOFF_RX_RING as i64,
                );
            }

            if rx_map == MAP_FAILED {
                err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();
                // goto out_put_ctx;

                return err;
            }

            unsafe {
                (*rx).mask = xsk.config.rx_size - 1;
                (*rx).size = xsk.config.rx_size;
                (*rx).producer = rx_map.add(off.rx.producer as usize) as *mut u32;
                (*rx).consumer = rx_map.add(off.rx.consumer as usize) as *mut u32;
                (*rx).flags = rx_map.add(off.rx.flags as usize) as *mut u32;
                (*rx).ring = rx_map.add(off.rx.desc as usize);
                (*rx).cached_prod = *(*rx).producer;
                (*rx).cached_cons = *(*rx).consumer;
            }
        }

        xsk.rx = rx;

        // tx mmap
        if !tx.is_null() {
            unsafe {
                tx_map = libc::mmap(
                    std::ptr::null_mut() as *mut std::ffi::c_void,
                    (off.tx.desc as usize)
                        + (xsk.config.tx_size as usize) * std::mem::size_of::<xdp_desc>(),
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_POPULATE,
                    xsk.fd,
                    XDP_PGOFF_TX_RING as i64,
                );
            }

            if tx_map == MAP_FAILED {
                err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();
                // goto out_mmap_rx;

                return err;
            }

            unsafe {
                (*tx).mask = xsk.config.tx_size - 1;
                (*tx).size = xsk.config.tx_size;
                (*tx).producer = tx_map.add(off.tx.producer as usize) as *mut u32;
                (*tx).consumer = tx_map.add(off.tx.consumer as usize) as *mut u32;
                (*tx).flags = tx_map.add(off.tx.flags as usize) as *mut u32;
                (*tx).ring = tx_map.add(off.tx.desc as usize);
                (*tx).cached_prod = *(*tx).producer;
                (*tx).cached_cons = *(*tx).consumer + xsk.config.tx_size;
            }
        }

        xsk.tx = tx;

        // Setup sockaddr
        sxdp.sxdp_family = PF_XDP as u16;
        sxdp.sxdp_ifindex = ctx.ifindex as u32;
        sxdp.sxdp_queue_id = ctx.queue_id;

        if umem.refcount > 1 {
            sxdp.sxdp_flags |= XDP_SHARED_UMEM as u16;
            sxdp.sxdp_shared_umem_fd = umem.fd as u32;
        } else {
            sxdp.sxdp_flags = xsk.config.bind_flags;
        }

        // Bind socket
        unsafe {
            err = libc::bind(
                xsk.fd,
                &sxdp as *const sockaddr_xdp as *const std::ffi::c_void as *const sockaddr,
                std::mem::size_of::<sockaddr_xdp>() as u32,
            );
        }

        if err != 0 {
            err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();
            // goto out_mmap_tx;

            return err;
        }

        // Setup xdp prog
        if (xsk.config.libbpf_flags & XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD) != 0 {
            // err = xsk_setup_xdp_prog(xsk);

            if err != 0 {
                // goto out_mmap_tx;

                return err;
            }
        }

        unsafe {
            (*xsk_ptr) = &mut xsk;
        }

        umem.fill_save = std::ptr::null_mut();
        umem.comp_save = std::ptr::null_mut();

        return 0;
    }

    pub fn set_socket_config(
        cfg: &mut xsk_socket_config,
        usr_cfg: &Option<xsk_socket_config>,
    ) -> i32 {
        match usr_cfg {
            Some(_usr_cfg) => {
                if (_usr_cfg.libbpf_flags & !(XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD)) != 0 {
                    return libc::EINVAL;
                }

                cfg.rx_size = _usr_cfg.rx_size;
                cfg.tx_size = _usr_cfg.tx_size;
                cfg.libbpf_flags = _usr_cfg.libbpf_flags;
                cfg.xdp_flags = _usr_cfg.xdp_flags;
                cfg.bind_flags = _usr_cfg.bind_flags;
            }

            None => {
                cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
                cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
                cfg.libbpf_flags = 0;
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
