// SPDX-License-Identifier: Apache-2.0
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| harpochat_server::fuzzing::envelope(data));
