use std::error::Error;
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug)]
pub struct TrieNode {
    l: Option<Box<TrieNode>>,
    r: Option<Box<TrieNode>>,
    v: Option<u32>,
}

impl TrieNode {
    /// Create a new empty trie node.
    pub fn empty() -> Self {
        TrieNode { l: None, r: None, v: None }
    }

    /// Create a new trie node with the provided values.
    pub fn new(left: Option<Box<TrieNode>>, right: Option<Box<TrieNode>>, value: Option<u32>) -> Self {
        TrieNode { l: left, r: right, v: value }
    }

    fn insert(&mut self, ip: u32, mask: u32, value: u32) {
        if mask == 0 {
            self.v = Some(value);
            return;
        }

        let next_node: &mut Option<Box<TrieNode>>
            = if ((1u32 << 31) & ip) == 0 { &mut self.l } else { &mut self.r };

        match next_node {
            Some(n) => n.insert(ip << 1, mask << 1, value),
            None => {
                let mut new_node = TrieNode::empty();
                new_node.insert(ip << 1, mask << 1, value);
                *next_node = Some(Box::new(new_node));
            },
        }
    }

    fn get(&self, ip: u32, mask: u32, buffer: &mut Vec<u32>) {
        if let Some(v) = self.v {
            buffer.push(v);
        }

        if mask == 0 {
            return;
        }

        if let Some(n) = if ((1u32 << 31) & ip) == 0 { &self.l } else { &self.r } {
            n.get(ip << 1, mask << 1, buffer);
        }
    }
}

#[derive(Debug)]
pub struct Trie {
    root: TrieNode,
}

impl Trie {
    /// Create a new empty trie.
    pub fn empty() -> Self {
        Trie { root: TrieNode::empty() }
    }

    /// Create a new trie with the provided node as root.
    pub fn new(root: TrieNode) -> Self {
        Trie { root }
    }

    /// Get the root node of the trie.
    pub fn root(&self) -> &TrieNode {
        &self.root
    }

    /// Insert a new cidr block with corresponding value to the trie.
    pub fn insert_cidr(&mut self, cidr: &str, value: u32) {
        let cidr_block = CidrBlock::from_str(cidr).unwrap();
        let mask: u32 = 0xffffffffu32 << (32 - cidr_block.prefix);
        self.root.insert(cidr_block.net, mask, value);
    }

    /// Get the values associated with the provided ip address.
    pub fn get(&self, ip: u32) -> Vec<u32> {
        let mut buffer: Vec<u32> = Vec::with_capacity(32);
        self.root.get(ip, 0xffffffffu32, &mut buffer);
        buffer
    }

    /// Get whether or not the trie contains the provided ip address.
    pub fn contains_ip(&self, ip: u32) -> bool {
        let mut buffer: Vec<u32> = Vec::with_capacity(32);
        self.root.get(ip, 0xffffffffu32, &mut buffer);
        buffer.len() != 0
    }
}

pub struct CidrBlock {
    pub net: u32,
    pub prefix: u32,
}

impl FromStr for CidrBlock {
    type Err = Box<dyn Error>;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.splitn(2, "/").collect();

        let net: Ipv4Addr = parts[0].parse()?;
        let prefix: u32 = parts[1].parse()?;

        Ok(CidrBlock {
            net: net.into(),
            prefix,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_block_from_str_ok() {
        let cb = CidrBlock::from_str("127.0.1.40/30").unwrap();
        assert_eq!(u32::from(Ipv4Addr::new(127, 0, 1, 40)), cb.net);
        assert_eq!(30, cb.prefix);
    }
}
