// Copyright 2016 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use table::{FullBucket, SafeHash, RawTable};
use entry::{self, VacantEntryState};
use Entry;

pub enum InternalEntry<K, V, M> {
    Occupied {
        elem: FullBucket<K, V, M>,
    },
    Vacant {
        hash: SafeHash,
        elem: VacantEntryState<K, V, M>,
    },
    TableIsEmpty,
}

impl<K, V, M> InternalEntry<K, V, M> {
    #[inline]
    pub fn into_occupied_bucket(self) -> Option<FullBucket<K, V, M>> {
        match self {
            InternalEntry::Occupied { elem } => Some(elem),
            _ => None,
        }
    }
}

impl<'a, K, V> InternalEntry<K, V, &'a mut RawTable<K, V>> {
    #[inline]
    pub fn into_entry(self, key: K) -> Option<Entry<'a, K, V>> {
        entry::from_internal(self, Some(key))
    }
}
