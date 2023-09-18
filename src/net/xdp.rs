use libc::{sockaddr, MAP_FAILED, MAP_POPULATE, MAP_SHARED, PROT_READ, PROT_WRITE, SOL_XDP};

use crate::buf::{BoundedBuf, BoundedBufMut};

use std::sync::atomic::{self, AtomicPtr};

//use libxdp_sys::{_xsk_ring_cons__peek, _xsk_ring_cons__release, _xsk_ring_cons__rx_desc};

const XSK_RING_CONS__DEFAULT_NUM_DESCS: u32 = 2048;
const XSK_RING_PROD__DEFAULT_NUM_DESCS: u32 = 2048;

const XSK_UMEM__DEFAULT_FRAME_SHIFT: u32 = 12; /* 4096 bytes */
const XSK_UMEM__DEFAULT_FRAME_SIZE: u32 = 1 << XSK_UMEM__DEFAULT_FRAME_SHIFT;
const XSK_UMEM__DEFAULT_FRAME_HEADROOM: u32 = 0;
const XSK_UMEM__DEFAULT_FLAGS: u32 = 0;

const XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD: u32 = 1 << 0;
const XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD: u32 = 1 << 0;

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

const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;

const XDP_SHARED_UMEM: u32 = 1 << 0;
const XDP_COPY: u32 = 1 << 1; /* Force copy-mode */
const XDP_ZEROCOPY: u32 = 1 << 2; /* Force zero-copy mode */

/* If this option is set, the driver might go sleep and in that case
 * the XDP_RING_NEED_WAKEUP flag in the fill and/or Tx rings will be
 * set. If it is set, the application need to explicitly wake up the
 * driver with a poll() (Rx and Tx) or sendto() (Tx only). If you are
 * running the driver and the application on the same core, you should
 * use this option so that the kernel will yield to the user space
 * application.
 */
const XDP_USE_NEED_WAKEUP: u32 = 1 << 3;

#[derive(Clone)]
pub struct XskCtx {
    fill: *mut XskRing,
    comp: *mut XskRing,
    umem: *mut XskUmem,
    queue_id: u32,
    refcount: i32,
    ifindex: i32,
    netns_cookie: u64,
    xsks_map_fs: i32,
    refcnt_map_fd: i32,
    ifname: String,
}

impl XskCtx {
    pub fn xsk_get_ctx(
        umem: &mut XskUmem,
        netns_cookie: u64,
        ifindex: i32,
        queue_id: u32,
    ) -> Option<Box<XskCtx>> {
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

    pub fn xsk_put_ctx(ctx: &mut XskCtx, unmap: bool) {
        let umem = ctx.umem;
        let mut off: XdpMmapOffsets = Default::default();
        let mut err = 0;

        if (ctx.refcount - 1) > 0 {
            return;
        }

        if unmap {
            unsafe {
                err = xsk_get_mmap_offsets((*umem).fd, &mut off);
            }

            if err != 0 {
                drop(ctx.to_owned());

                return;
            }

            unsafe {
                libc::munmap(
                    (*ctx.fill).ring,
                    (off.fr.desc as usize)
                        + ((*umem).config.fill_size as usize) * std::mem::size_of::<u64>(),
                );

                libc::munmap(
                    (*ctx.fill).ring,
                    (off.cr.desc as usize)
                        + ((*umem).config.comp_size as usize) * std::mem::size_of::<u64>(),
                );
            }

            drop(ctx.to_owned());
        }
    }

    pub fn xsk_create_ctx(
        xsk: &XskSocket,
        umem: &mut XskUmem,
        netns_cookie: u64,
        ifindex: i32,
        ifname: &String,
        queue_id: u32,
        fill: *mut XskRing,
        comp: *mut XskRing,
    ) -> Option<XskCtx> {
        let mut err: i32 = 0;
        let mut ctx: Box<XskCtx> = Default::default();

        if umem.fill_save.is_null() {
            err = xsk_create_umem_rings(umem, xsk.fd, fill, comp);

            if err != 0 {
                return None;
            }
        } else if (umem.fill_save != fill) || (umem.comp_save != comp) {
            // TODO: Copy data
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
}

impl Default for XskCtx {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

pub struct XskSocketConfig {
    pub rx_size: u32,
    pub tx_size: u32,
    pub libbpf_flags: u32,
    pub xdp_flags: u32,
    pub bind_flags: u16,
}

pub struct XskUmem {
    pub fill_save: *mut XskRing,
    pub comp_save: *mut XskRing,
    pub umem_area: *mut std::ffi::c_void,
    pub config: XskUmemConfig,
    pub fd: i32,
    pub refcount: i32,
    pub ctx_list: std::collections::LinkedList<Box<XskCtx>>,
    pub rx_ring_setup_done: bool,
    pub tx_ring_setup_done: bool,
}

impl XskUmem {
    pub fn new<T: BoundedBufMut>(
        area: &mut T,
        completion_ring_size: u32,
        fill_ring_size: u32,
    ) -> Result<XskUmem, i32> {
        // Check that ring sizes are both powers of two.

        // Init Umem config
        let umem_cfg = XskUmemConfig {
            fill_size: fill_ring_size,
            comp_size: completion_ring_size,
            frame_size: area.bytes_total() as u32,
            frame_headroom: XSK_UMEM__DEFAULT_FRAME_HEADROOM,
            flags: 0,
        };

        // Allocate rings on the heap
        let mut cq: Box<XskRing> = Default::default();
        let mut fq: Box<XskRing> = Default::default();

        // Setup umem size - buffer length * no of buffers
        let size = area.bytes_total() as u64;

        let fd: i32 = -1;

        // Call inner create function
        let umem = XskUmem::create(
            fd,
            size,
            area.stable_mut_ptr() as *mut std::ffi::c_void,
            fq.as_mut(),
            cq.as_mut(),
            &Some(umem_cfg),
        );

        umem
    }

    pub fn create(
        fd: i32, // TODO: Should be Option<i32>
        size: u64,
        umem_area: *mut std::ffi::c_void,
        fill: &mut XskRing,
        comp: &mut XskRing,
        usr_config: &Option<XskUmemConfig>,
    ) -> Result<XskUmem, i32> {
        let mut mr: XskUmemReg = Default::default();
        let mut umem: Box<XskUmem> = Default::default();
        let mut err = 0;

        if umem_area.is_null() {
            return Err(-libc::EFAULT);
        }

        if (size == 0) && !(xsk_page_aligned(umem_area)) {
            return Err(-libc::EINVAL);
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

            return Err(err);
        }

        umem.umem_area = umem_area;

        XskUmem::set_umem_config(&mut umem.config, usr_config);

        mr.addr = umem_area as u64;
        mr.len = size;
        mr.chunk_size = umem.config.frame_size;
        mr.headroom = umem.config.frame_headroom;
        mr.flags = umem.config.flags;

        // Apply Umem settings through libc::setsockopt()
        unsafe {
            err = libc::setsockopt(
                umem.fd,
                SOL_XDP,
                XDP_UMEM_REG as i32,
                &mr as *const XskUmemReg as *const std::ffi::c_void,
                std::mem::size_of_val(&mr) as u32,
            )
        }

        if err != 0 {
            err = -std::io::Error::last_os_error().raw_os_error().unwrap();

            unsafe {
                libc::close(fd);
            }
            drop(umem);

            return Err(err);
        }

        let fd_temp = umem.fd;

        err = xsk_create_umem_rings(&mut umem, fd_temp, fill, comp);

        if err != 0 {
            unsafe {
                libc::close(fd);
            }
            drop(umem);

            return Err(err);
        }

        umem.fill_save = fill;
        umem.comp_save = comp;

        Ok(*umem)
    }

    pub fn set_umem_config(cfg: &mut XskUmemConfig, usr_cfg: &Option<XskUmemConfig>) {
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

    pub fn fill<T: BoundedBufMut>(
        &mut self,
        prod: &mut XskRing,
        bufs: &mut Vec<T>,
        mut batch_size: usize,
    ) -> usize {
        let mut idx: u32 = 0;
        let reserved: u32;

        batch_size = std::cmp::min(bufs.len(), batch_size);

        if batch_size == 0 {
            return 0;
        }

        reserved = XskRing::xsk_ring_prod_reserve(prod, batch_size as u32, &mut idx);

        for _ in 0..reserved {
            let buf = bufs.pop();

            match buf {
                Some(buf) => unsafe {
                    let ptr = XskRing::xsk_ring_prod_fill_addr(prod, idx);
                    idx += 1;

                    *ptr = buf.stable_ptr().sub(self.umem_area as usize) as u64;
                },
                None => {}
            }
        }

        if reserved > 0 {
            XskRing::xsk_ring_prod_submit(prod, reserved);
        }

        reserved as usize
    }
}

impl Default for XskUmem {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

pub struct XskUmemConfig {
    pub fill_size: u32,
    pub comp_size: u32,
    pub frame_size: u32,
    pub frame_headroom: u32,
    pub flags: u32,
}

#[repr(C)]
pub struct XskUmemReg {
    pub addr: u64,
    pub len: u64,
    pub chunk_size: u32,
    pub headroom: u32,
    pub flags: u32,
}

impl Default for XskUmemReg {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

pub struct XskRing {
    pub cached_prod: u32,
    pub cached_cons: u32,
    pub mask: u32,
    pub size: u32,
    pub producer: *mut u32,
    pub consumer: *mut u32,
    pub ring: *mut std::ffi::c_void,
    pub flags: *mut u32,
}

impl XskRing {
    pub fn xsk_cons_nb_avail(r: &mut XskRing, nb: u32) -> u32 {
        let mut entries: u32 = 0;

        unsafe {
            entries = r.cached_prod - r.cached_cons;
            let atomic_producer = AtomicPtr::new(r.producer);

            if entries == 0 {
                r.cached_prod = *(atomic_producer.load(atomic::Ordering::Acquire));
                entries = r.cached_prod - r.cached_prod;
            }
        }

        if entries > nb {
            nb
        } else {
            entries
        }
    }

    pub fn xsk_ring_cons_peek(cons: &mut XskRing, nb: u32, idx: &mut u32) -> u32 {
        let entries = XskRing::xsk_cons_nb_avail(cons, nb);

        if entries > 0 {
            *idx = cons.cached_cons;
            cons.cached_cons += entries;
        }

        entries
    }

    pub fn xsk_ring_cons_rx_desc(rx: &XskRing, idx: u32) -> *const XdpDesc {
        unsafe {
            let descs: *const XdpDesc = rx.ring as *const XdpDesc;

            let descs = std::slice::from_raw_parts(descs, (rx.mask) as usize);

            &descs[(idx & rx.mask) as usize]
        }
    }

    pub fn xsk_ring_cons_release(cons: &mut XskRing, nb: u32) {
        unsafe {
            let atomic_consumer = AtomicPtr::new(cons.consumer);

            let mut value = *(cons.consumer) + nb;

            atomic_consumer.store(&mut value, atomic::Ordering::Release)
        }
    }

    pub fn xsk_ring_cons_comp_addr(comp: &XskRing, idx: u32) -> *mut u64 {
        unsafe {
            let addrs: *mut u64 = comp.ring as *mut u64;

            let addrs = std::slice::from_raw_parts_mut(addrs, comp.mask as usize);

            let ret = &mut addrs[(idx & comp.mask) as usize];

            ret
        }
    }

    pub fn xsk_prod_nb_free(r: &mut XskRing, nb: u32) -> u32 {
        let free_entries: u32 = r.cached_cons - r.cached_prod;

        if free_entries >= nb {
            return free_entries;
        }

        let atomic_consumer = AtomicPtr::new(r.consumer);

        unsafe {
            r.cached_cons = *(atomic_consumer.load(atomic::Ordering::Acquire));
        }

        r.cached_cons += r.size;

        r.cached_cons - r.cached_prod
    }

    pub fn xsk_ring_prod_reserve(prod: &mut XskRing, nb: u32, idx: &mut u32) -> u32 {
        if XskRing::xsk_prod_nb_free(prod, nb) < nb {
            return 0;
        }

        *idx = prod.cached_prod;
        prod.cached_prod += nb;

        nb
    }

    pub fn xsk_ring_prod_fill_addr(fill: &mut XskRing, idx: u32) -> *mut u64 {
        unsafe {
            let addrs: *mut u64 = fill.ring as *mut u64;

            let addrs = std::slice::from_raw_parts_mut(addrs, fill.mask as usize);

            let ret = &mut addrs[(idx & fill.mask) as usize];

            ret
        }
    }

    pub fn xsk_ring_prod_submit(prod: &mut XskRing, nb: u32) {
        unsafe {
            let atomic_producer = AtomicPtr::new(prod.producer);

            let mut value = *(prod.producer) + nb;

            atomic_producer.store(&mut value, atomic::Ordering::Release);
        }
    }
}

impl Default for XskRing {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

#[repr(C)]
pub struct XdpRingOffsets {
    pub producer: u64,
    pub consumer: u64,
    pub desc: u64,
    pub flags: u64,
}

#[repr(C)]
pub struct XdpMmapOffsets {
    pub rx: XdpRingOffsets,
    pub tx: XdpRingOffsets,
    pub fr: XdpRingOffsets,
    pub cr: XdpRingOffsets,
}

impl Default for XdpMmapOffsets {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

#[repr(C)]
pub struct XdpDesc {
    pub addr: u64,
    pub len: u32,
    pub options: u32,
}

pub struct SockaddrXdp {
    pub sxdp_family: u16,
    pub sxdp_flags: u16,
    pub sxdp_ifindex: u32,
    pub sxdp_queue_id: u32,
    pub sxdp_shared_umem_fd: u32,
}

impl Default for SockaddrXdp {
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
    umem: &mut XskUmem,
    fd: i32,
    fill: *mut XskRing,
    comp: *mut XskRing,
) -> i32 {
    let mut off: XdpMmapOffsets = Default::default();
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

    // Setup struct for fill ring.
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

/*pub fn xsk_setup_xdp_program(xsk: &mut xsk_socket, xsks_map_fs: i32) -> i32 {
    let mut ctx = xsk.ctx;

    unsafe {
        (*ctx).
        (*ctx).refcnt_map_fd = -libc::ENOENT;
    }

    0
}*/

pub fn xsk_get_mmap_offsets(fd: i32, off: &mut XdpMmapOffsets) -> i32 {
    let mut err: i32 = 0;
    let mut optlen: u32 = 0;

    optlen = std::mem::size_of_val(off) as u32;

    unsafe {
        err = libc::getsockopt(
            fd,
            SOL_XDP,
            XDP_MMAP_OFFSETS as i32,
            off as *mut XdpMmapOffsets as *mut std::ffi::c_void,
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

pub struct XskSocket {
    rx: *mut XskRing,
    tx: *mut XskRing,
    ctx: *mut XskCtx,
    config: XskSocketConfig,
    fd: i32,
}

impl XskSocket {
    pub fn new(
        umem: &mut XskUmem,
        if_name: &str,
        queue: usize,
        rx_ring_size: u32,
        tx_ring_size: u32,
        //options: SocketOptions,
    ) -> Result<XskSocket, i32> {
        // Check that the ring sizes are both powers of two.

        // Setup socket options
        let socket_config = XskSocketConfig {
            rx_size: rx_ring_size,
            tx_size: tx_ring_size,
            xdp_flags: XDP_FLAGS_UPDATE_IF_NOEXIST,
            bind_flags: (XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY) as u16,
            libbpf_flags: 0,
        };

        // Allocate rings on the heap
        let mut rx: Box<XskRing> = Default::default();
        let mut tx: Box<XskRing> = Default::default();

        // Call inner create function
        let xsk = XskSocket::create(
            &if_name.to_string(),
            queue as u32,
            umem,
            rx.as_mut(),
            tx.as_mut(),
            &Some(socket_config),
        );

        xsk
    }

    // Must already have umem
    pub fn create(
        ifname: &String,
        queue_id: u32,
        umem: &mut XskUmem,
        rx: *mut XskRing,
        tx: *mut XskRing,
        usr_config: &Option<XskSocketConfig>,
    ) -> Result<XskSocket, i32> {
        let mut rx_setup_done: bool = false;
        let mut tx_setup_done: bool = false;
        let mut err: i32 = 0;
        let mut ifindex: i32 = 0;
        let mut netns_cookie: u64 = 0;
        let mut optlen: u32 = 0;
        let mut off: XdpMmapOffsets = Default::default();
        let mut rx_map: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut tx_map: *mut std::ffi::c_void = std::ptr::null_mut();
        let mut sxdp: SockaddrXdp = Default::default();

        let fill = umem.fill_save;
        let comp = umem.comp_save;

        // Check that we have the necessary valid pointers.
        if rx.is_null() && tx.is_null() {
            return Err(-libc::EFAULT);
        }

        // Allocate xsk_socket on the heap.
        let mut xsk: Box<XskSocket> = Default::default();

        // Set xdp_socket_config
        err = XskSocket::set_socket_config(&mut xsk.config, usr_config);

        if err != 0 {
            drop(xsk);

            return Err(err);
        }

        // Get interface index from name
        unsafe {
            ifindex = libc::if_nametoindex(ifname.as_bytes() as *const [u8] as *const i8) as i32;
        }

        if ifindex == 0 {
            err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();

            drop(xsk);

            return Err(err);
        }

        // Check if umem refcount is greater than zero. If it is, then the umem is shared and we need our own file descriptor for the AF_XDP socket, otherwise we can use the same file descriptor as the Umem.
        if umem.refcount > 0 {
            unsafe {
                xsk.fd = libc::socket(AF_XDP as i32, SOCK_RAW as i32, 0);
            }

            if xsk.fd < 0 {
                err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();

                drop(xsk);

                return Err(err);
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

                // out_socket
                if (umem.refcount - 1) == 0 {
                    unsafe {
                        libc::close(xsk.fd);
                    }
                }

                // out_xsk_alloc
                drop(xsk);

                return Err(err);
            }

            netns_cookie = INIT_NS as u64;
        }

        // Get the correct umem context for this particular AF_XDP socket. If no existing context exists then we create a new context and add it to the list.
        let mut ctx = match XskCtx::xsk_get_ctx(umem, netns_cookie, ifindex, queue_id) {
            Some(_ctx) => *_ctx,
            None => {
                if fill.is_null() || comp.is_null() {
                    err = -libc::EFAULT;

                    // out_socket
                    if (umem.refcount - 1) == 0 {
                        unsafe {
                            libc::close(xsk.fd);
                        }
                    }

                    // out_xsk_alloc
                    drop(xsk);

                    return Err(err);
                }

                let ctx = match XskCtx::xsk_create_ctx(
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
                        // out_socket
                        if (umem.refcount - 1) == 0 {
                            unsafe {
                                libc::close(xsk.fd);
                            }
                        }

                        // out_xsk_alloc
                        drop(xsk);

                        return Err(-libc::ENOMEM);
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

                // out_put_ctx
                let unmap = umem.fill_save != fill;

                XskCtx::xsk_put_ctx(&mut ctx, unmap);

                // out_socket
                if (umem.refcount - 1) == 0 {
                    unsafe {
                        libc::close(xsk.fd);
                    }
                }

                // out_xsk_alloc
                drop(xsk);

                return Err(err);
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

                // out_put_ctx
                let unmap = umem.fill_save != fill;

                XskCtx::xsk_put_ctx(&mut ctx, unmap);

                // out_socket
                if (umem.refcount - 1) == 0 {
                    unsafe {
                        libc::close(xsk.fd);
                    }
                }

                // out_xsk_alloc
                drop(xsk);

                return Err(err);
            }

            if xsk.fd == umem.fd {
                umem.tx_ring_setup_done = true;
            }
        }

        // Get mmap offsets
        err = xsk_get_mmap_offsets(xsk.fd, &mut off);

        if err != 0 {
            err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();

            // out_put_ctx
            let unmap = umem.fill_save != fill;

            XskCtx::xsk_put_ctx(&mut ctx, unmap);

            // out_socket
            if (umem.refcount - 1) == 0 {
                unsafe {
                    libc::close(xsk.fd);
                }
            }

            // out_xsk_alloc
            drop(xsk);

            return Err(err);
        }

        // rx mmap
        if !rx.is_null() {
            unsafe {
                rx_map = libc::mmap(
                    std::ptr::null_mut() as *mut std::ffi::c_void,
                    (off.rx.desc as usize)
                        + (xsk.config.rx_size as usize) * std::mem::size_of::<XdpDesc>(),
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_POPULATE,
                    xsk.fd,
                    XDP_PGOFF_RX_RING as i64,
                );
            }

            if rx_map == MAP_FAILED {
                err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();

                // out_put_ctx
                let unmap = umem.fill_save != fill;

                XskCtx::xsk_put_ctx(&mut ctx, unmap);

                // out_socket
                if (umem.refcount - 1) == 0 {
                    unsafe {
                        libc::close(xsk.fd);
                    }
                }

                // out_xsk_alloc
                drop(xsk);

                return Err(err);
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
                        + (xsk.config.tx_size as usize) * std::mem::size_of::<XdpDesc>(),
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_POPULATE,
                    xsk.fd,
                    XDP_PGOFF_TX_RING as i64,
                );
            }

            if tx_map == MAP_FAILED {
                err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();

                // out_mmap_rx
                if !(rx.is_null()) {
                    unsafe {
                        libc::munmap(
                            rx_map,
                            (off.rx.desc as usize)
                                + (xsk.config.rx_size as usize)
                                + std::mem::size_of::<XdpDesc>(),
                        );
                    }
                }

                // out_put_ctx
                let unmap = umem.fill_save != fill;

                XskCtx::xsk_put_ctx(&mut ctx, unmap);

                // out_socket
                if (umem.refcount - 1) == 0 {
                    unsafe {
                        libc::close(xsk.fd);
                    }
                }

                // out_xsk_alloc
                drop(xsk);

                return Err(err);
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
                &sxdp as *const SockaddrXdp as *const std::ffi::c_void as *const sockaddr,
                std::mem::size_of::<SockaddrXdp>() as u32,
            );
        }

        if err != 0 {
            err = 0 - std::io::Error::last_os_error().raw_os_error().unwrap();

            // out_mmap_tx
            if !(tx.is_null()) {
                unsafe {
                    libc::munmap(
                        tx_map,
                        (off.tx.desc as usize)
                            + (xsk.config.tx_size as usize)
                            + std::mem::size_of::<XdpDesc>(),
                    );
                }
            }

            // out_mmap_rx
            if !(rx.is_null()) {
                unsafe {
                    libc::munmap(
                        rx_map,
                        (off.rx.desc as usize)
                            + (xsk.config.rx_size as usize)
                            + std::mem::size_of::<XdpDesc>(),
                    );
                }
            }

            // out_put_ctx
            let unmap = umem.fill_save != fill;

            XskCtx::xsk_put_ctx(&mut ctx, unmap);

            // out_socket
            if (umem.refcount - 1) == 0 {
                unsafe {
                    libc::close(xsk.fd);
                }
            }

            // out_xsk_alloc
            drop(xsk);

            return Err(err);
        }

        // Setup xdp prog
        if (xsk.config.libbpf_flags & XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD) == 0 {
            // err = xsk_setup_xdp_prog(xsk);

            if err != 0 {
                // goto out_mmap_tx;

                return Err(err);
            }
        }

        umem.fill_save = std::ptr::null_mut();
        umem.comp_save = std::ptr::null_mut();

        return Ok(*xsk);
    }

    pub fn set_socket_config(cfg: &mut XskSocketConfig, usr_cfg: &Option<XskSocketConfig>) -> i32 {
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

    pub async fn sendmsg<T: BoundedBuf>(&self, _buf: Vec<T>) {
        //libxdp_sys::sendmsg;
    }

    pub async fn recvmsg<T: BoundedBufMut>(&self, _buf: Vec<T>)
    /*-> crate::BufResult<(usize, std::net::SocketAddr), Vec<T>>*/
    {
    }

    pub fn try_recv<T: BoundedBufMut>(&mut self, bufs: Vec<T>, mut batch_size: usize) -> usize {
        let mut idx = 0;
        let received: usize;

        batch_size = std::cmp::min(bufs.capacity(), batch_size);

        unsafe {
            received =
                XskRing::xsk_ring_cons_peek(self.rx.as_mut().unwrap(), batch_size as u32, &mut idx)
                    as usize;
        }

        if received == 0 {
            return 0;
        }

        //let buf_len_available = ;

        for _ in 0..received {
            let desc: *const XdpDesc;
            let buf: T;

            unsafe {
                desc = XskRing::xsk_ring_cons_rx_desc(self.rx.as_mut().unwrap(), idx);

                let addr = (*desc).addr;
                let len = (*desc).len;
                let ptr = (*((*(self.ctx)).umem)).umem_area.add(addr as usize);

                //buf.get_buf().put_slice(src)

                //buf.
            }
        }

        unsafe {
            XskRing::xsk_ring_cons_release(self.rx.as_mut().unwrap(), received as u32);
        }

        received
    }

    /*#[inline]
    pub fn try_recv(
        &mut self,
        bufs: &mut ArrayDeque<[BufMmap<T>; PENDING_LEN], Wrapping>,
        mut batch_size: usize,
        user: T,
    ) -> Result<usize, SocketError> {
        let mut idx_rx: u32 = 0;
        let rcvd: usize;

        batch_size = min(bufs.capacity() - bufs.len(), batch_size);

        unsafe {
            rcvd = _xsk_ring_cons__peek(self.rx.as_mut(), batch_size as u64, &mut idx_rx) as usize;
        }
        if rcvd == 0 {
            // Note that the caller needs to check if the queue needs to be woken up
            return Ok(0);
        }

        let buf_len_available = self.socket.umem.area.get_buf_len() - AF_XDP_RESERVED as usize;

        for _ in 0..rcvd {
            let desc: *const xdp_desc;
            let b: BufMmap<T>;

            unsafe {
                desc = _xsk_ring_cons__rx_desc(self.rx.as_mut(), idx_rx);
                let addr = (*desc).addr;
                let len = (*desc).len.try_into().unwrap();
                let ptr = self.socket.umem.area.get_ptr().offset(addr as isize);

                b = BufMmap {
                    addr,
                    len,
                    data: std::slice::from_raw_parts_mut(ptr as *mut u8, buf_len_available),
                    user,
                };
            }

            let r = bufs.push_back(b);

            if r.is_some() {
                // Since we set batch_size above based on how much space there is, this should
                // never happen.
                panic!("there should be space");
            }

            idx_rx += 1;
        }

        unsafe {
            _xsk_ring_cons__release(self.rx.as_mut(), rcvd as u64);
        }

        Ok(rcvd)
    }*/
}

impl Default for XskSocket {
    fn default() -> Self {
        let mut s = ::std::mem::MaybeUninit::<Self>::uninit();
        unsafe {
            ::std::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}
