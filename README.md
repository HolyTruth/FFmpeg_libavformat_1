# FFmpeg_libavformat_1
# CVE 申请文案 — F1（HEIF tmap 断言崩溃）— 2026-11-15

## Vulnerability description
FFmpeg master (commit 09382db7f5791362dcaf0f4f26fad2bb18cb0dcb) is prone to a
reachable assertion abort in libavformat/mov.c when demuxing a crafted HEIF
file. A `tmap` derived-image group whose `infe` item_id collides with a
previously created video stream causes the item to hold both an AVStream and
an AVStreamGroup, tripping `av_assert0(!st != !child_stg)` at
libavformat/mov.c:11644. Any application demuxing untrusted input aborts
(SIGABRT, exit 134) — deterministic denial of service. 416-byte testcase.

## Root cause (validated by human review and container reproduction)
1. `mov_read_infe()` (mov.c:9639-9672) accepts duplicate item_ids; the
   pre-existing AVStream is not removed on overwrite.
2. The `tmap` group path (mov.c ~:11778) creates an AVStreamGroup and also
   invokes `heif_add_stream` (~:5921), leaving both `st` and `child_stg` set.
3. `av_assert0(!st != !child_stg)` (mov.c:11644) aborts on the both-set state.
   Four sibling assertions of the same shape exist (mov.c:11814/11825/11915/11926).

## CWE
CWE-617 (Reachable Assertion) leading to CWE-400-class deterministic DoS.

## Affected product / versions
- Product: FFmpeg, libavformat (mov.c / HEIF demuxer).
- Verified present: upstream master 09382db7f5791362dcaf0f4f26fad2bb18cb0dcb
  (2026-11-15) — code path confirmed; reproduction on 2026-11-12 snapshot
  (post-n9.1), unmodified configure.
- No release known to be fixed.

## Reproduction
- Command: `ffprobe -v warning crash.mp4`
- Testcase: 416-byte crash.mp4; generator script gen_heif_tmap2.py.
- Result: `Assertion !st != !child_stg failed at libavformat/mov.c:11644`
  (SIGABRT, exit 134). Deterministic.


## References
- Testcase + generator
- FFmpeg security policy: https://www.ffmpeg.org/security.html
