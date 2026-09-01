use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use rustls::ServerConfig;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct LeafCacheKey {
    pub(super) host: String,
    pub(super) alpn: Option<Vec<u8>>,
}

#[derive(Debug)]
pub(super) struct LeafCache {
    capacity: usize,
    entries: HashMap<LeafCacheKey, Arc<ServerConfig>>,
    recency: VecDeque<LeafCacheKey>,
}

impl LeafCache {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::new(),
            recency: VecDeque::new(),
        }
    }

    pub(super) fn get(&mut self, key: &LeafCacheKey) -> Option<Arc<ServerConfig>> {
        let config = self.entries.get(key).cloned()?;
        self.recency.retain(|candidate| candidate != key);
        self.recency.push_back(key.clone());
        Some(config)
    }

    pub(super) fn insert(&mut self, key: LeafCacheKey, value: Arc<ServerConfig>) {
        if self.capacity == 0 {
            return;
        }
        if self.entries.len() == self.capacity
            && let Some(oldest) = self.recency.pop_front()
        {
            self.entries.remove(&oldest);
        }
        self.recency.push_back(key.clone());
        self.entries.insert(key, value);
    }
}
