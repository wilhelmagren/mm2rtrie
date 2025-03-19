/// A node in the trie.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IpTrieNode<V> {
    left: Option<Box<IpTrieNode<V>>>,
    right: Option<Box<IpTrieNode<V>>>,
    value: Option<V>,
}

impl<V> IpTrieNode<V> {
    /// Create a new empty trie node.
    pub fn empty() -> Self {
        IpTrieNode { left: None, right: None, value: None }
    }

    /// Create a new trie node with provided values.
    pub fn new(l: Option<Box<IpTrieNode<V>>>, r: Option<Box<IpTrieNode<V>>>, v: Option<V>) -> Self {
        IpTrieNode { left: l, right: r, value: v }
    }

    /// Get whether this is a leaf node or not.
    ///
    /// A leaf node will contain a value, all other nodes do not contain values.
    pub fn is_leaf(&self) -> bool {
        self.value.is_none()
    }

    pub fn insert(&mut self, ip: u32, mask: u32, value: V) {
        if mask == 0 {
            self.value = Some(value);
            return;
        }

        let bit: u32 = 1u32 << 31;
        let next_node: &mut Option<Box<IpTrieNode<V>>>
            = if (ip & bit) == 0 { &mut self.left } else { &mut self.right };

        match next_node {
            Some(n) => n.insert(ip << 1, mask << 1, value),
            None => {
                let mut new_node: IpTrieNode<V> = IpTrieNode::empty();
                new_node.insert(ip << 1, mask << 1, value);
                *next_node = Some(Box::new(new_node));
            },
        }
    }
}

/// Implementation of a binary trie.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct IpTrie<V> {
    root: IpTrieNode<V>,
}

