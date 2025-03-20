use bincode::{Decode, Encode, config};

use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter};
use std::net::Ipv4Addr;
use std::str::FromStr;

#[derive(Debug, Decode, Encode, Eq, PartialEq)]
pub struct TrieNode<V> {
    l: Option<Box<TrieNode<V>>>,
    r: Option<Box<TrieNode<V>>>,
    v: Option<Vec<V>>,
}

impl<V> TrieNode<V> {
    /// Create a new empty trie node.
    pub fn empty() -> Self {
        TrieNode { l: None, r: None, v: None }
    }

    /// Create a new trie node with the provided values.
    pub fn new(left: Option<Box<TrieNode<V>>>, right: Option<Box<TrieNode<V>>>, value: Option<Vec<V>>) -> Self {
        TrieNode { l: left, r: right, v: value }
    }

    fn insert(&mut self, ip: u32, mask: u32, value: V) {
        if mask == 0 {
            if let Some(v) = &mut self.v {
                v.push(value);
            } else {
                self.v = Some(vec![value]);
            }
            return;
        }

        let next_node: &mut Option<Box<TrieNode<V>>>
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

    fn get<'a>(&'a self, ip: u32, mask: u32, buffer: &mut Vec<&'a V>) {
        if let Some(v) = &self.v {
            buffer.extend(v);
        }

        if mask == 0 {
            return;
        }

        if let Some(n) = if ((1u32 << 31) & ip) == 0 { &self.l } else { &self.r } {
            n.get(ip << 1, mask << 1, buffer);
        }
    }
}

#[derive(Debug, Decode, Encode, Eq, PartialEq)]
pub struct Trie<V> {
    root: TrieNode<V>,
}

impl<V: Decode<()> + Encode> Trie<V>
{
    /// Create a new empty trie.
    pub fn empty() -> Self {
        Trie { root: TrieNode::empty() }
    }

    /// Create a new trie with the provided node as root.
    pub fn new(root: TrieNode<V>) -> Self {
        Trie { root }
    }

    /// Get the root node of the trie.
    pub fn root(&self) -> &TrieNode<V> {
        &self.root
    }

    /// Insert a new cidr block with corresponding value to the trie.
    pub fn insert_cidr(&mut self, cidr: &str, value: V) {
        let cidr_block = CidrBlock::from_str(cidr).unwrap();
        let mask: u32 = 0xffffffffu32 << (32 - cidr_block.prefix);
        self.root.insert(cidr_block.net, mask, value);
    }

    /// Insert a new cidr block by its net and prefix values.
    pub fn insert_net_and_prefix(&mut self, net: u32, prefix: u32, value: V) {
        let mask: u32 = 0xffffffffu32 << (32 - prefix);
        self.root.insert(net, mask, value);
    }

    /// Get the values associated with the provided ip address.
    pub fn get(&self, ip: u32) -> Vec<&V> {
        let mut buffer: Vec<&V> = Vec::with_capacity(32);
        self.root.get(ip, 0xffffffffu32, &mut buffer);
        buffer
    }

    /// Get whether or not the trie contains the provided ip address.
    pub fn contains_ip(&self, ip: u32) -> bool {
        let mut buffer: Vec<&V> = Vec::with_capacity(32);
        self.root.get(ip, 0xffffffffu32, &mut buffer);
        buffer.len() != 0
    }

    /// Initialize a Trie instance that was saved to a binary file.
    pub fn read_from_file(path: &str) -> Self {
        let config: config::Configuration = config::standard();
        let file: File = match OpenOptions::new()
            .read(true)
            .write(false)
            .open(path) {
            Ok(f) => f,
            Err(_) => {
                println!("{} did not exist, creating an empty Trie...", path);
                return Trie::empty();
            },
        };

        let mut reader: BufReader<File> = BufReader::new(file);
        bincode::decode_from_std_read(&mut reader, config).unwrap()
    }

    /// Write the state of the Trie to binary file.
    pub fn write_to_file(&self, path: &str) {
        let config: config::Configuration = config::standard();
        let file: File = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();

        let mut writer: BufWriter<File> = BufWriter::new(file);
        bincode::encode_into_std_write(&self, &mut writer, config).unwrap();
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

    #[derive(Clone, Debug, Decode, Encode, Eq, PartialEq)]
    struct TestDummyStruct {
        pub a: u32,
        pub b: bool,
        pub c: String,
    }

    #[test]
    fn trie_with_custom_struct() {
        let mut t: Trie<TestDummyStruct> = Trie::empty();
        let tds = TestDummyStruct {
            a: 23,
            b: true,
            c: "Hello Radix Trie!".to_string(),
        };
        t.insert_net_and_prefix(Ipv4Addr::new(183, 40, 20, 0).into(), 8, tds.clone());
        assert_eq!(vec![&tds], t.get(Ipv4Addr::new(183, 41, 24, 249).into()));
        assert_eq!(23, t.get(Ipv4Addr::new(183, 41, 24, 249).into())[0].a);
    }

    #[test]
    fn trie_with_many_custom_struct() {
        let mut t: Trie<TestDummyStruct> = Trie::empty();
        let tds1 = TestDummyStruct {
            a: 1,
            b: true,
            c: "Hello Radix Trie!".to_string(),
        };
        let tds2 = TestDummyStruct {
            a: 69,
            b: false,
            c: "Goodbye...".to_string(),
        };
        let tds3 = TestDummyStruct {
            a: 420,
            b: true,
            c: "Don't you dare go hollow.".to_string(),
        };

        t.insert_net_and_prefix(Ipv4Addr::new(183, 210, 129, 0).into(), 2, tds1.clone());
        t.insert_net_and_prefix(Ipv4Addr::new(183, 40, 31, 0).into(), 8, tds2.clone());
        t.insert_net_and_prefix(Ipv4Addr::new(10, 123, 42, 0).into(), 24, tds3.clone());

        let g = t.get(Ipv4Addr::new(183, 123, 59, 3).into());
        assert_eq!(vec![&tds1, &tds2], g);

        let gg = t.get(Ipv4Addr::new(10, 123, 42, 250).into());
        assert_eq!(vec![&tds3], gg);
        assert_eq!(Vec::<&TestDummyStruct>::new(), t.get(Ipv4Addr::new(20, 159, 30, 42).into()));
    }

    #[test]
    fn insert_from_net_and_prefix() {
        let mut t: Trie<u32> = Trie::empty();
        t.insert_net_and_prefix(Ipv4Addr::new(183, 40, 20, 0).into(), 8, 49);
        t.insert_net_and_prefix(Ipv4Addr::new(183, 40, 21, 3).into(), 16, 150);
        t.insert_net_and_prefix(Ipv4Addr::new(20, 30, 40, 0).into(), 31, 420);

        assert_eq!(false, t.contains_ip(Ipv4Addr::new(182, 41, 21, 3).into()));
        assert_eq!(vec![&49, &150], t.get(Ipv4Addr::new(183, 40, 25, 59).into()));
        assert_eq!(vec![&420], t.get(Ipv4Addr::new(20, 30, 40, 1).into()));
    }

    #[test]
    fn cidr_block_from_str_ok() {
        let cb = CidrBlock::from_str("127.0.1.40/30").unwrap();
        assert_eq!(u32::from(Ipv4Addr::new(127, 0, 1, 40)), cb.net);
        assert_eq!(30, cb.prefix);
    }

    #[test]
    fn write_and_load_trie_ok() {
        let mut t = Trie::empty();
        t.insert_cidr("50.178.3.0/16", 3);
        t.insert_cidr("214.0.0.0/24", 128);
        t.write_to_file("./test-trie.bin");

        assert_eq!(true, t.contains_ip(Ipv4Addr::new(50, 178, 3, 6).into()));
        assert_eq!(vec![&128], t.get(Ipv4Addr::new(214, 0, 0, 39).into()));

        let mut tt = Trie::read_from_file("./test-trie.bin");
        assert_eq!(t, tt);

        tt.insert_cidr("33.12.14.0/24", 420);
        assert_eq!(false, t.contains_ip(Ipv4Addr::new(33, 12, 14, 15).into()));
        assert_eq!(true, tt.contains_ip(Ipv4Addr::new(33, 12, 14, 15).into()));
    }
}
