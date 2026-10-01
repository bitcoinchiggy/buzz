# Fork fix: mesh demo echo drain tick

This page records a bitcoinchiggy/buzz patch that upstream
`d56ed75424d803cf29b2f1f4f430ee81dc145f92` does not contain. It does
not deploy, publish, or change an image.

## The patch

`run_demo_echo` in `crates/buzz-relay/src/mesh_boot.rs` pins the
`recv_validated` future and races a mutable reference to it against the
100ms drain interval. Commit
`322c7a9590da8339d87666dcc6d7fc93b9f5c23a`.

Upstream `tokio::select!` drops every branch it does not take.
`tokio::time::interval` completes its first tick immediately.
`recv_validated` reads a QUIC frame before the Redis fence await, so
that drop discards the frame. The forwarder in
`api::mesh_demo::tests::demo_join_forwarded_arm_round_trips_echo` then
waits out `ECHO_TIMEOUT` (10s) and returns HTTP 504.

The round-trip assertion and `ECHO_TIMEOUT` are unchanged. The
huddle-control `select!` in `crates/buzz-relay/src/audio/join.rs` is
not part of this patch.

`mesh_boot::tests::demo_echo_drain_tick_does_not_drop_in_flight_frame`
holds the only frame for 300ms, longer than the drain period, and
expects the echoed payload `mesh echo evidence`. On the upstream
`select!` it fails with `drain tick dropped the in-flight echo frame`.
The test reaches Redis through `REDIS_URL` or
`redis://127.0.0.1:6379`. If that connection or `PING` fails, the test
returns before the assertion. A pass proves the pin only when Redis
answered. The harness time for a real run is about 0.32s because of
the 300ms hold; an early return finishes in a few milliseconds.

## Upstream reproduction

These runs used one disposable Redis at `127.0.0.1:6379`, `FLUSHALL`
before each run, and `--test-threads=1`. Sources were unmodified.

At merge commit `10c267a2587c6be1a86d7b02db1a5b9866a3e58c` the test,
`run_demo_echo`, `crates/buzz-relay/src/tunnel/reliable.rs`, and
`crates/buzz-relay-mesh/src/peer.rs` match upstream `d56ed754`. That
commit: 4 pass, 4 fail. Each failure was status 504 against the
expected 200, at about 10.05–10.10s.

Upstream `d56ed754`, separate worktree and cargo target directory:
2 pass, 6 fail. Same 504, at about 10.05–10.07s.

Deployed fork `c663342af551caa7596a0a48778bd20d5be26a84` has the same
test, `run_demo_echo`, `reliable.rs`, and `peer.rs`. That commit was
compared and not executed. `directory.rs` differs there; this test
builds the directory with `db: None` and a random community, so that
difference is not on the path that returned 504.

## When to remove it

Delete this patch, its regression test, and this page after an
upstream commit is merged here and all of the following are true on
that upstream commit:

1. `run_demo_echo` keeps an in-flight `recv_validated` when the drain
   tick fires. Pinning the future and selecting on `&mut`, or another
   change that preserves a frame already read from the QUIC stream,
   qualifies. A longer `ECHO_TIMEOUT`, or a weaker check than HTTP 200
   and payload `mesh echo evidence`, does not.
2. A test on that commit fails when the receive future is dropped
   across the drain tick, and passes when the read stays alive.
3. Serial repeats of `demo_join_forwarded_arm_round_trips_echo`, with
   Redis flushed between runs, no longer fail with 504 the way
   `d56ed754` did (6 of 8 unmodified runs failed there).

If the upstream change supersedes the pin, do not keep both.
