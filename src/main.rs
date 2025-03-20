pub mod radix_trie;
pub mod util;

use radix_trie::Trie;
use util::{generate_cidr_blocks, generate_ips};

use rand::{rngs::ThreadRng, Rng};
use rayon::iter::ParallelIterator;
use rayon::prelude::IntoParallelRefIterator;

use std::time::Instant;


fn main() {
    let n_cidr_blocks: usize = 64_000;
    println!("Generating {} CIDR blocks", n_cidr_blocks);
    let cidr_blocks: Vec<(u32, u32)> = generate_cidr_blocks(n_cidr_blocks);

    let mut t: Trie<u32> = Trie::empty();
    println!("Inserting CIDR blocks to Trie");
    let mut thread_rng: ThreadRng = rand::rng();
    for (net, prefix) in cidr_blocks.into_iter() {
        t.insert_net_and_prefix(net, prefix, thread_rng.random());
    }

    let n_ips: usize = 50_000_000;
    println!("Generating {} ips for lookup", n_ips);
    let ips: Vec<u32> = generate_ips(n_ips);

    println!("Starting timer, performing {} lookups...", n_ips);

    let start = Instant::now();
    let n_hits: usize = ips.par_iter()
        .map(|ip| {
            t.get(*ip).len()
        })
        .collect::<Vec<usize>>().into_iter().sum();
    let elapsed = start.elapsed();

    println!(
        "\nSTATS:\nElapsed {:?} ms for {:?} ip lookups, {:?} ns per lookup",
        elapsed.as_millis() as f64,
        n_ips, 
        elapsed.as_nanos() as f64 / n_ips as f64,
    );

    println!("Got {} lookup hits", n_hits);
    println!("Example hit: ip={}, values:{:?}", ips[23], t.get(ips[23]));

    println!("Writing trie to file 'trie.bin'");
    // t.write_to_file("trie.bin");
}
