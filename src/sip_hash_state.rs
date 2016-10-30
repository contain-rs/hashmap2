// Copyright 2016 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::hash::{BuildHasher, SipHasher13};
use rand::{self, Rng};

/// `SipHashState` is the default state for `HashMap` types.
///
/// A particular instance `SipHashState` will create the same instances of
/// `Hasher`, but the hashers created by two different `SipHashState`
/// instances are unlikely to produce the same result for the same values.
#[derive(Clone)]
pub struct SipHashState {
    k0: u64,
    k1: u64,
}

impl SipHashState {
    /// Constructs a new `SipHashState` that is initialized with random keys.
    #[inline]
    #[allow(deprecated)] // rand
    pub fn new() -> SipHashState {
        thread_local!(static KEYS: (u64, u64) = {
            let r = rand::OsRng::new();
            let mut r = r.expect("failed to create an OS RNG");
            (r.gen(), r.gen())
        });

        KEYS.with(|&(k0, k1)| {
            SipHashState { k0: k0, k1: k1 }
        })
    }
}

impl BuildHasher for SipHashState {
    type Hasher = SipHasher13;
    #[inline]
    fn build_hasher(&self) -> SipHasher13 {
        SipHasher13::new_with_keys(self.k0, self.k1)
    }
}
