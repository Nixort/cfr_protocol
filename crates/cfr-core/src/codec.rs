// Copyright Nixort <https://github.com/Nixort> 2026.
//
// License: GNU General Public License v3.0 only.
// You can find the license file in the project root.
//
// Causal Frontier Ratchet (CFR).

//! Canonical bounded TLV codec.
use crate::error::{Error, Result};
use alloc::vec::Vec;

const T_BYTES: u8 = 1;
const T_U64: u8 = 2;
const T_STR: u8 = 3;
const T_LIST: u8 = 4;
const T_SET: u8 = 5;

/// Hard ceiling on any single length field, so a corrupt header cannot cause a
/// multi-gigabyte allocation (obligation O13).
pub const MAX_FIELD: usize = 1 << 22;
/// Hard ceiling on the number of elements in a list or set.
pub const MAX_ITEMS: usize = 1 << 16;

/// Canonical TLV writer.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    /// A new empty writer.
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Consumes the writer and returns the encoded bytes.
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// The bytes written so far.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Writes a byte string.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.push(T_BYTES);
        self.buf.extend_from_slice(
            &u32::try_from(v.len())
                .expect("field length fits u32")
                .to_be_bytes(),
        );
        self.buf.extend_from_slice(v);
        self
    }

    /// Writes an unsigned 64-bit integer in fixed width.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.push(T_U64);
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Writes an unsigned 32-bit integer, widened. There is one integer type on
    /// the wire so that `u32` and `u64` of equal value cannot differ in image.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.u64(u64::from(v))
    }

    /// Writes a UTF-8 string.
    pub fn str(&mut self, v: &str) -> &mut Self {
        self.buf.push(T_STR);
        self.buf.extend_from_slice(
            &u32::try_from(v.len())
                .expect("field length fits u32")
                .to_be_bytes(),
        );
        self.buf.extend_from_slice(v.as_bytes());
        self
    }

    /// Writes an ordered list. The closure encodes each element.
    pub fn list<T, F>(&mut self, items: &[T], mut f: F) -> &mut Self
    where
        F: FnMut(&mut Writer, &T),
    {
        self.buf.push(T_LIST);
        self.buf.extend_from_slice(
            &u32::try_from(items.len())
                .expect("item count fits u32")
                .to_be_bytes(),
        );
        for it in items {
            f(self, it);
        }
        self
    }

    /// Writes a set: elements are encoded, then sorted by image, then emitted.
    ///
    /// Sorting by *image* rather than by the caller's element ordering is what
    /// makes the encoding independent of iteration order, and therefore makes
    /// the operation identifier independent of the sender's internal state.
    pub fn set<T, F>(&mut self, items: &[T], mut f: F) -> &mut Self
    where
        F: FnMut(&mut Writer, &T),
    {
        let mut images: Vec<Vec<u8>> = Vec::with_capacity(items.len());
        for it in items {
            let mut w = Writer::new();
            f(&mut w, it);
            images.push(w.finish());
        }
        images.sort_unstable();
        images.dedup();
        self.buf.push(T_SET);
        self.buf.extend_from_slice(
            &u32::try_from(images.len())
                .expect("item count fits u32")
                .to_be_bytes(),
        );
        for img in images {
            self.buf.extend_from_slice(&img);
        }
        self
    }
}

/// Canonical TLV reader. Rejects any encoding its own writer would not produce.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wraps a byte slice.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Returns an error unless every byte has been consumed. Trailing data is a
    /// canonicity violation: it would let an attacker append bytes to a signed
    /// image without changing its meaning to a lax parser.
    pub fn finish(self) -> Result<()> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(Error::Encoding("trailing bytes"))
        }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::Encoding("truncated"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn tag(&mut self, want: u8) -> Result<()> {
        let got = *self.take(1)?.first().expect("one byte taken");
        if got == want {
            Ok(())
        } else {
            Err(Error::Encoding("unexpected type tag"))
        }
    }

    fn len32(&mut self, limit: usize) -> Result<usize> {
        let raw: [u8; 4] = self.take(4)?.try_into().expect("four bytes taken");
        let n = u32::from_be_bytes(raw) as usize;
        if n > limit {
            return Err(Error::Encoding("length exceeds limit"));
        }
        Ok(n)
    }

    /// Reads a byte string.
    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        self.tag(T_BYTES)?;
        let n = self.len32(MAX_FIELD)?;
        self.take(n)
    }

    /// Reads a byte string of exactly `N` bytes.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let b = self.bytes()?;
        b.try_into()
            .map_err(|_| Error::Encoding("wrong field width"))
    }

    /// Reads a `u64`.
    pub fn u64(&mut self) -> Result<u64> {
        self.tag(T_U64)?;
        let raw: [u8; 8] = self.take(8)?.try_into().expect("eight bytes taken");
        Ok(u64::from_be_bytes(raw))
    }

    /// Reads a `u32`, rejecting values that do not fit.
    pub fn u32(&mut self) -> Result<u32> {
        u32::try_from(self.u64()?).map_err(|_| Error::Encoding("integer out of range"))
    }

    /// Reads a UTF-8 string.
    pub fn str(&mut self) -> Result<&'a str> {
        self.tag(T_STR)?;
        let n = self.len32(MAX_FIELD)?;
        core::str::from_utf8(self.take(n)?).map_err(|_| Error::Encoding("invalid utf-8"))
    }

    /// Reads an ordered list.
    pub fn list<T, F>(&mut self, mut f: F) -> Result<Vec<T>>
    where
        F: FnMut(&mut Reader<'a>) -> Result<T>,
    {
        self.tag(T_LIST)?;
        let n = self.len32(MAX_ITEMS)?;
        let mut out = Vec::with_capacity(n.min(1024));
        for _ in 0..n {
            out.push(f(self)?);
        }
        Ok(out)
    }

    /// Reads a set, enforcing strictly ascending image order.
    ///
    /// This check is what makes decoding canonical: a set that arrives unsorted
    /// or with duplicates is rejected rather than silently normalised, because
    /// silent normalisation would give one value two valid images.
    pub fn set<T, F>(&mut self, mut f: F) -> Result<Vec<T>>
    where
        F: FnMut(&mut Reader<'a>) -> Result<T>,
    {
        self.tag(T_SET)?;
        let n = self.len32(MAX_ITEMS)?;
        let mut out = Vec::with_capacity(n.min(1024));
        let mut prev_end = self.pos;
        let mut prev: Option<&[u8]> = None;
        for _ in 0..n {
            let start = self.pos;
            let item = f(self)?;
            let image = &self.buf[start..self.pos];
            if let Some(p) = prev {
                if image <= p {
                    return Err(Error::Encoding("set not in canonical order"));
                }
            }
            prev = Some(image);
            prev_end = self.pos;
            out.push(item);
        }
        let _ = prev_end;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn roundtrip_primitives() {
        let mut w = Writer::new();
        w.bytes(b"abc").u64(7).str("hi").u32(9);
        let buf = w.finish();
        let mut r = Reader::new(&buf);
        assert_eq!(r.bytes().unwrap(), b"abc");
        assert_eq!(r.u64().unwrap(), 7);
        assert_eq!(r.str().unwrap(), "hi");
        assert_eq!(r.u32().unwrap(), 9);
        r.finish().unwrap();
    }

    #[test]
    fn field_boundaries_are_unambiguous() {
        // The A5 property at the encoding layer: splitting the same bytes
        // differently gives a different image.
        let mut a = Writer::new();
        a.bytes(b"ab").bytes(b"c");
        let mut b = Writer::new();
        b.bytes(b"a").bytes(b"bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn integer_and_bytes_do_not_collide() {
        let mut a = Writer::new();
        a.u64(0);
        let mut b = Writer::new();
        b.bytes(&[0u8; 8]);
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn set_image_is_order_independent() {
        let mk = |v: &[&[u8]]| {
            let mut w = Writer::new();
            w.set(v, |w, x| {
                w.bytes(x);
            });
            w.finish()
        };
        assert_eq!(
            mk(&[b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]),
            mk(&[b"c".as_slice(), b"a".as_slice(), b"b".as_slice()])
        );
    }

    #[test]
    fn set_duplicates_collapse_on_write() {
        let mut w = Writer::new();
        w.set(&[b"a".as_slice(), b"a".as_slice()], |w, x| {
            w.bytes(x);
        });
        let buf = w.finish();
        let mut r = Reader::new(&buf);
        let got: Vec<&[u8]> = r.set(super::Reader::bytes).unwrap();
        assert_eq!(got, vec![b"a".as_slice()]);
    }

    #[test]
    fn unsorted_set_is_rejected_on_read() {
        // Hand-build a set whose elements descend. A lax parser would accept
        // it, giving one value two images and breaking A5.
        let mut inner_b = Writer::new();
        inner_b.bytes(b"b");
        let mut inner_a = Writer::new();
        inner_a.bytes(b"a");
        let mut buf = vec![T_SET];
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(inner_b.as_slice());
        buf.extend_from_slice(inner_a.as_slice());
        let mut r = Reader::new(&buf);
        let got: Result<Vec<&[u8]>> = r.set(super::Reader::bytes);
        assert!(matches!(got, Err(Error::Encoding(_))));
    }

    #[test]
    fn duplicate_set_element_is_rejected_on_read() {
        let mut inner = Writer::new();
        inner.bytes(b"a");
        let mut buf = vec![T_SET];
        buf.extend_from_slice(&2u32.to_be_bytes());
        buf.extend_from_slice(inner.as_slice());
        buf.extend_from_slice(inner.as_slice());
        let mut r = Reader::new(&buf);
        let got: Result<Vec<&[u8]>> = r.set(super::Reader::bytes);
        assert!(matches!(got, Err(Error::Encoding(_))));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut w = Writer::new();
        w.u64(1);
        let mut buf = w.finish();
        buf.push(0);
        let mut r = Reader::new(&buf);
        r.u64().unwrap();
        assert!(r.finish().is_err());
    }

    #[test]
    fn oversize_length_is_rejected_without_allocating() {
        let mut buf = vec![T_BYTES];
        buf.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut r = Reader::new(&buf);
        assert!(matches!(r.bytes(), Err(Error::Encoding(_))));
    }

    #[test]
    fn wrong_tag_is_rejected() {
        let mut w = Writer::new();
        w.u64(1);
        let buf = w.finish();
        let mut r = Reader::new(&buf);
        assert!(r.bytes().is_err());
    }
}
