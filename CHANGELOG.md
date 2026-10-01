# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **A partly written relay batch is no longer dropped.** When the batched
  send wrote fewer messages than it was given without returning an error (a
  short `sendmmsg`, or any platform without it, where one message is sent per
  call), the rest of the batch was discarded. The remainder is now sent
  per-packet.

### Changed
- **The per-source relay limit is 4000 packets a second, up from 1000.** The
  limit counts packets. Daemons are moving from ~4.2 KB stream datagrams
  (which IP fragmented) to ~1.2 KB ones that fit a single packet, so the same
  traffic is about 3.5 times as many packets; 4000 keeps the limit where it
  was in bytes (about 4 MB/s per source).

## [v0.1.0]

Initial release.
