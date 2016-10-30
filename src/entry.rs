// Copyright 2016 The Rust Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution and at
// http://rust-lang.org/COPYRIGHT.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::mem;

use table::{EmptyBucket, FullBucket, SafeHash, RawTable};
use internal_entry::InternalEntry;
use pop_internal;
use robin_hood;
use adaptive_map;

pub use self::Entry::*;
pub use self::VacantEntryState::*;

/// A view into a single location in a map, which may be vacant or occupied.
pub enum Entry<'a, K: 'a, V: 'a> {
    /// An occupied Entry.
    Occupied(OccupiedEntry<'a, K, V>),

    /// A vacant Entry.
    Vacant(VacantEntry<'a, K, V>),
}

/// A view into a single occupied location in a HashMap.
pub struct OccupiedEntry<'a, K: 'a, V: 'a> {
    key: Option<K>,
    elem: FullBucket<K, V, &'a mut RawTable<K, V>>,
}

/// A view into a single empty location in a HashMap.
pub struct VacantEntry<'a, K: 'a, V: 'a> {
    hash: SafeHash,
    key: K,
    reduce_displacement_flag: Option<&'a mut bool>,
    elem: VacantEntryState<K, V, &'a mut RawTable<K, V>>,
}

/// Possible states of a VacantEntry.
pub enum VacantEntryState<K, V, M> {
    /// The index is occupied, but the key to insert has precedence,
    /// and will kick the current one out on insertion.
    NeqElem(FullBucket<K, V, M>, usize),
    /// The index is genuinely vacant.
    NoElem(EmptyBucket<K, V, M>),
}

impl<'a, K, V> Entry<'a, K, V> {
    /// Returns the entry key
    ///
    /// # Examples
    ///
    /// ```
    /// use hashmap2::HashMap;
    ///
    /// let mut map = HashMap::<String, u32>::new();
    ///
    /// assert_eq!("hello", map.entry("hello".to_string()).key());
    /// ```
    pub fn key(&self) -> &K {
        match *self {
            Occupied(ref entry) => entry.key(),
            Vacant(ref entry) => entry.key(),
        }
    }

    /// Ensures a value is in the entry by inserting the default if empty, and returns
    /// a mutable reference to the value in the entry.
    pub fn or_insert(self, default: V) -> &'a mut V {
        match self {
            Occupied(entry) => entry.into_mut(),
            Vacant(entry) => entry.insert(default),
        }
    }

    /// Ensures a value is in the entry by inserting the result of the default function if empty,
    /// and returns a mutable reference to the value in the entry.
    pub fn or_insert_with<F: FnOnce() -> V>(self, default: F) -> &'a mut V {
        match self {
            Occupied(entry) => entry.into_mut(),
            Vacant(entry) => entry.insert(default()),
        }
    }
}

impl<'a, K, V> OccupiedEntry<'a, K, V> {
    /// Gets a reference to the value in the entry.
    pub fn get(&self) -> &V {
        self.elem.read().1
    }

    /// Gets a mutable reference to the value in the entry.
    pub fn get_mut(&mut self) -> &mut V {
        self.elem.read_mut().1
    }

    /// Converts the OccupiedEntry into a mutable reference to the value in the entry
    /// with a lifetime bound to the map itself
    pub fn into_mut(self) -> &'a mut V {
        self.elem.into_mut_refs().1
    }

    /// Sets the value of the entry, and returns the entry's old value
    pub fn insert(&mut self, mut value: V) -> V {
        let old_value = self.get_mut();
        mem::swap(&mut value, old_value);
        value
    }

    /// Takes the value out of the entry, and returns it
    pub fn remove(self) -> V {
        pop_internal(self.elem).1
    }

    /// Gets a reference to the entry key
    ///
    /// # Examples
    ///
    /// ```
    /// use hashmap2::HashMap;
    ///
    /// let mut map = HashMap::new();
    ///
    /// map.insert("foo".to_string(), 1);
    /// assert_eq!("foo", map.entry("foo".to_string()).key());
    /// ```
    pub fn key(&self) -> &K {
        self.elem.read().0
    }

    /// Returns a key that was used for search.
    ///
    /// The key was retained for further use.
    pub fn take_key(&mut self) -> Option<K> {
        self.key.take()
    }
}

impl<'a, K: 'a, V: 'a> VacantEntry<'a, K, V> {
    /// Sets the value of the entry with the VacantEntry's key,
    /// and returns a mutable reference to it
    pub fn insert(self, value: V) -> &'a mut V {
        match self.elem {
            NeqElem(bucket, ib) => {
                robin_hood(bucket, ib, self.hash, self.key, value, self.reduce_displacement_flag)
            }
            NoElem(bucket) => {
                let bucket = bucket.put(self.hash, self.key, value);
                adaptive_map::safeguard_insertion(&bucket, self.reduce_displacement_flag);
                bucket.into_mut_refs().1
            }
        }
    }

    /// Gets a reference to the entry key
    ///
    /// # Examples
    ///
    /// ```
    /// use hashmap2::HashMap;
    ///
    /// let mut map = HashMap::<String, u32>::new();
    ///
    /// assert_eq!("foo", map.entry("foo".to_string()).key());
    /// ```
    pub fn key(&self) -> &K {
        &self.key
    }

    pub fn set_flag_for_reduce_displacement(&mut self, flag: &'a mut bool) {
        self.reduce_displacement_flag = Some(flag);
    }
}

// These fns are public, but the entire module is not.

#[inline]
pub fn from_internal<K, V>(internal: InternalEntry<K, V, &mut RawTable<K, V>>, key: Option<K>)
                          -> Option<Entry<K, V>> {
    match internal {
        InternalEntry::Occupied { elem } => {
            Some(Entry::Occupied(OccupiedEntry {
                key: key,
                elem: elem
            }))
        }
        InternalEntry::Vacant { hash, elem } => {
            Some(Entry::Vacant(VacantEntry {
                hash: hash,
                key: key.unwrap(),
                reduce_displacement_flag: None,
                elem: elem,
            }))
        }
        InternalEntry::TableIsEmpty => None
    }
}

#[inline]
pub fn occupied_elem<'a, 'r, K, V>(occupied: &'r mut OccupiedEntry<'a, K, V>)
                         -> &'r mut FullBucket<K, V, &'a mut RawTable<K, V>> {
    &mut occupied.elem
}
