use std::{
    ffi::c_int,
    io,
    mem::{self},
};

use bytemuck::NoUninit;
use compio::{
    buf::{IoBuf, IoBufMut, SetLen, Slice},
    io::framed::{
        codec::{Decoder, Encoder},
        frame::{Frame, Framer},
    },
};
use libc::{CMSG_NXTHDR, cmsghdr, msghdr};

const HEADER_SIZE: usize = mem::size_of::<libc::cmsghdr>();

#[repr(align(8))]
pub struct AncillaryBuf<const N: usize> {
    buf: [u8; N],
    init: usize,
}

impl<const N: usize> AncillaryBuf<N> {
    fn new() -> Self {
        Self {
            buf: [0; N],
            init: 0,
        }
    }

    fn remaining_capacity(&self) -> usize {
        N - self.init
    }

    fn header(&self) -> libc::msghdr {
        let mut hdr = unsafe { mem::zeroed::<msghdr>() };

        hdr.msg_control = self.buf.as_ptr() as *mut _;
        hdr.msg_controllen = self.buf.len();

        hdr
    }
}

impl<const N: usize> IoBuf for AncillaryBuf<N> {
    fn as_init(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.buf.as_ptr() as _, self.init) }
    }
}

impl<const N: usize> SetLen for AncillaryBuf<N> {
    unsafe fn set_len(&mut self, len: usize) {
        assert!(len <= N);
        self.init = len;
    }
}

impl<const N: usize> IoBufMut for AncillaryBuf<N> {
    fn as_uninit(&mut self) -> &mut [std::mem::MaybeUninit<u8>] {
        self.buf.as_uninit()
    }
}

pub struct AncillaryFramer;

impl<const N: usize> Framer<AncillaryBuf<N>> for AncillaryFramer {
    fn enclose(&mut self, _: &mut AncillaryBuf<N>) {}

    fn extract(&mut self, buf: &Slice<AncillaryBuf<N>>) -> io::Result<Option<Frame>> {
        if buf.len() < HEADER_SIZE {
            return Ok(None);
        }

        let hdr = buf.as_inner().header();
        let curr = buf.buf_ptr().cast::<cmsghdr>();

        let next = unsafe { CMSG_NXTHDR(&raw const hdr, curr) };
        let len = unsafe { curr.as_ref() }.unwrap().cmsg_len;

        // We have tested that the buffer has at least the header size. If NXTHDR
        // returns null, it means that the header length is invalid (e.g., too small),
        // so we can return an error.
        if next.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ancillary data length",
            ));
        }

        let suffix = unsafe { next.byte_offset_from_unsigned(curr as *mut cmsghdr) } - len;

        Ok(Some(Frame::new(0, len, suffix)))
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CMsg<T> {
    cmsg_level: c_int,
    cmsg_type: c_int,
    data: T,
}

pub struct AncillaryEncoder;

impl<const N: usize, T: NoUninit> Encoder<CMsg<T>, AncillaryBuf<N>> for AncillaryEncoder {
    type Error = io::Error;

    fn encode(&mut self, item: CMsg<T>, buf: &mut AncillaryBuf<N>) -> Result<(), Self::Error> {
        let len = std::mem::size_of::<T>();
        let total = HEADER_SIZE + len;
        if buf.remaining_capacity() < total {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "not enough capacity for ancillary data",
            ));
        }

        let hdr = unsafe { &mut *(buf.buf.as_mut_ptr() as *mut cmsghdr) };
        hdr.cmsg_level = item.cmsg_level;
        hdr.cmsg_type = item.cmsg_type;
        hdr.cmsg_len = total as _;

        let ptr = unsafe { buf.buf.as_mut_ptr().add(HEADER_SIZE) };

        unsafe { std::ptr::copy_nonoverlapping(&raw const item.data as _, ptr, len) };
        unsafe { buf.advance(total) };

        Ok(())
    }
}

impl<const N: usize, T: NoUninit> Decoder<CMsg<T>, AncillaryBuf<N>> for AncillaryEncoder {
    type Error = io::Error;

    fn decode(&mut self, buf: &Slice<AncillaryBuf<N>>) -> Result<CMsg<T>, Self::Error> {
        if buf.len() < HEADER_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough data for ancillary header",
            ));
        }

        let hdr = unsafe { buf.as_ptr().cast::<cmsghdr>().as_ref() }.unwrap();
        let data_ptr = unsafe { buf.as_ptr().add(HEADER_SIZE) };

        if buf.len() < HEADER_SIZE + hdr.cmsg_len as usize {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "not enough data for ancillary payload",
            ));
        }

        let data = unsafe { std::ptr::read_unaligned(data_ptr as *const T) };

        Ok(CMsg {
            cmsg_level: hdr.cmsg_level,
            cmsg_type: hdr.cmsg_type,
            data,
        })
    }
}
