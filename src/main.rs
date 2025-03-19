fn main() {
    println!("{:08b} {:08b}", 0x80000000u32, 1u32 << 31);
    assert_eq!(0x80000000u32, 1u32 << 31);
}
