pub mod radix_trie;

use radix_trie::Trie;

use std::net::Ipv4Addr;


fn main() {
    let mut t = Trie::empty();
    t.insert_cidr("50.178.3.0/16", 3);
    t.insert_cidr("1.2.3.4/32", 1337);
    t.insert_cidr("214.0.0.0/24", 128);
    t.insert_cidr("214.1.1.0/24", 986123);
    t.insert_cidr("50.178.3.5/29", 45);
    println!("Trie contains 50.178.3.6 ? {}", t.contains_ip(Ipv4Addr::new(50, 178, 3, 6).into()));
    println!("Trie contains 214.1.2.3 ? {}", t.contains_ip(Ipv4Addr::new(214, 1, 2, 3).into()));
    println!("Trie get on 214.1.2.3 : {:?}", t.get(Ipv4Addr::new(214, 1, 2, 3).into()));

    t.insert_cidr("192.168.0.1/32", 8172864);
    println!("Trie contains 192.168.0.1 ? {}", t.contains_ip(Ipv4Addr::new(192, 168, 0, 1).into()));
    println!("Trie get on 192.168.0.1 : {:?}", t.get(Ipv4Addr::new(192, 168, 0, 1).into()));
    println!("Trie contains 192.168.0.2 ? {}", t.contains_ip(Ipv4Addr::new(192, 168, 0, 2).into()));
    println!("Trie get on 192.168.0.2 : {:?}", t.get(Ipv4Addr::new(192, 168, 0, 2).into()));

    t.insert_cidr("33.12.14.0/24", 420);
    t.insert_cidr("33.12.0.0/16", 69);
    println!("Trie contains 33.12.14.15 ? {}", t.contains_ip(Ipv4Addr::new(33, 12, 14, 15).into()));
    println!("Trie get on 33.12.14.15 : {:?}", t.get(Ipv4Addr::new(33, 12, 14, 15).into()));
}
