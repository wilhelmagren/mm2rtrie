use rand::prelude::*;
use rand::Rng;

/// Generate n number of random cidr blocks.
/// Net parts in the range [0, u32::MAX] and prefix part in [0, 32] since its IPv4.
pub fn generate_cidr_blocks(n: usize) -> Vec<(u32, u32)> {
    let mut thread_rng: ThreadRng = rand::rng();
    (0..n)
        .map(|_| (thread_rng.random_range(0u32..u32::MAX), thread_rng.random_range(0u32..32u32)))
        .collect()
}

/// Split the CIDR block into its u32 parts (net, prefix).
pub fn cidr_to_u32_parts(cidr: &str) -> (u32, u32) {
    let mut parts = cidr.split("/");
    let ip = parts.next().unwrap();
    let prefix: u32 = parts.next().unwrap().parse().unwrap();

    let ip_parts: Vec<u32> = ip.split(".").into_iter()
        .map(|p| p.parse().unwrap()).collect();

    let mut ipint: u32 = 0;

    for (i, num) in ip_parts.iter().enumerate() {
        ipint += num * (256u32.pow(3u32 - (i as u32)) as u32);
    }

    (ipint, prefix)
}
