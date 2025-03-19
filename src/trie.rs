use chrono::prelude::*;
use maxminddb::geoip2;

pub struct GeoRecord<'a> {
    city: geoip2::City<'a>,
    country: geoip2::Country<'a>,
    insert_utc: DateTime<Utc>,
    is_latest: bool,
}

pub struct TrieNode<'a> {
    left: Option<Box<TrieNode<'a>>>,
    right: Option<Box<TrieNode<'a>>>,
    value: Option<Vec<GeoRecord<'a>>>,
}

impl<'a> TrieNode<'a> {
    pub fn empty() -> Self {
        TrieNode { left: None, right: None, value: None }
    }

    pub fn new(
        left: Option<Box<TrieNode<'a>>>,
        right: Option<Box<TrieNode<'a>>>,
        value: Option<Vec<GeoRecord<'a>>>,
    ) -> Self {
        TrieNode { left, right, value }
    }

    pub fn is_leaf(&self) -> bool {
        self.value.is_none()
    }

    pub fn insert(&mut self, ip: u32, mask: u32, value: GeoRecord<'a>) {
        if mask == 0 {
            match self.value.as_mut() {
                Some(v) => v.push(value),
                None => self.value = Some(vec![value]),
            };
            return;
        };
    }
}
