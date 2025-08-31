use rug::{Integer, ops::Pow, rand::RandState};
use std::collections::HashSet;

pub trait RugIntoBytes {
    fn to_bytes(&self) -> Vec<u8>;
}

impl RugIntoBytes for Integer {
    fn to_bytes(&self) -> Vec<u8> {
        // Least significant first.
        let mut val = self.clone();
        let mut bytes = vec![];

        while !val.is_zero() {
            bytes.push((val.clone() & Integer::from(0xFF)).to_u8().unwrap());
            val >>= 8;
        }

        bytes
    }
}

pub fn generate_point_mod(rng: &mut RandState, p: &Integer) -> Integer {
    Integer::from(p.random_below_ref(rng))
}

pub fn generate_unique_point_mod(
    rng: &mut RandState,
    p: &Integer,
    points: &mut HashSet<Integer>,
) -> Integer {
    loop {
        let point = generate_point_mod(rng, p);
        if points.insert(point.clone()) {
            return point;
        }
    }
}

pub fn generate_unique_flagless_point_mod(
    rng: &mut RandState,
    p: &Integer,
    points: &mut HashSet<Integer>,
) -> Integer {
    // Ensures the most significant bit, when packed to fit the bit length of p, is 0.
    // To be correct, p should be of the form 2**n - 1 for some integer n.
    loop {
        let point = Integer::from(
            p.clone()
                .set_bit(p.significant_bits() - 1, false)
                .random_below_ref(rng),
        );
        if points.insert(point.clone()) {
            return point;
        }
    }
}

pub fn generate_n_points_mod(rng: &mut RandState, n: u32, p: &Integer) -> Vec<Integer> {
    let mut points = vec![];
    for _ in 0..n {
        points.push(generate_point_mod(rng, p))
    }

    points
}

pub fn get_eligible_bits_of_nth_size(n: u32, p: &Integer) -> u32 {
    // Returns the `m`-th mask of one-"n"th the bit length of `p`.
    let mut eligible_bits = p.significant_bits() / n;

    if eligible_bits * n == p.significant_bits() {
        let max_arbitrary_nth_mask: Integer =
            (Integer::from(2).pow(eligible_bits) - 1) << (eligible_bits * (n - 1));
        if max_arbitrary_nth_mask.clone() & p < max_arbitrary_nth_mask {
            eligible_bits -= 1;
        }
    }

    eligible_bits
}

pub fn get_mth_mask_of_nth_size(m: u32, n: u32, p: &Integer) -> Integer {
    // Returns the `m`-th mask from the left of size one-"n"th the bit length of `p`.
    let eligible_bits = get_eligible_bits_of_nth_size(n, p);
    if eligible_bits == 0 {
        panic!("Cannot generate a value of 1/{n} bit length of {p}.");
    }

    if m > n || m == 0 {
        panic!("Mask index {m} is out of bounds for 1/{n} bit length of {p}.");
    }

    (Integer::from(Integer::ONE << eligible_bits) - 1)
        << (eligible_bits * (p.significant_bits() / eligible_bits - m))
}

pub fn generate_part_of_one_nth_size(rng: &mut RandState, n: u32, p: &Integer) -> Integer {
    // Generates a random number `v` of one-"n"th the bit length of `p`.
    // Ensures that `n` concatenations of any arbitrary `v` is always less than `p`.
    let eligible_bits = get_eligible_bits_of_nth_size(n, p);

    if eligible_bits == 0 {
        panic!("Cannot generate a value of 1/{n} bit length of {p}.");
    }

    Integer::from(Integer::from(Integer::ONE << eligible_bits).random_below_ref(rng))
}

pub fn get_parts_of_one_nth_size<const N: usize>(x: &Integer, p: &Integer) -> [Integer; N] {
    let eligible_bits = get_eligible_bits_of_nth_size(N.try_into().unwrap(), p);
    if eligible_bits == 0 {
        panic!("Cannot generate a value of 1/{N} bit length of {p}.");
    }

    let mut parts = vec![];
    let mask: Integer = Integer::from(Integer::ONE << eligible_bits) - 1;
    for i in (0..N).rev() {
        parts.push(Integer::from(x >> (eligible_bits * i as u32)) & mask.clone());
    }

    parts.try_into().unwrap()
}

pub fn pack_nth_parts_into_size(parts: Vec<Integer>, n: u32, p: &Integer) -> Integer {
    // Packs n "n"th-sized parts of `p` into a single `p`-sized value.
    if parts.len() != n as usize {
        panic!(
            "Expected {n} parts to pack, but got {} ({parts:?}).",
            parts.len()
        );
    }

    let max_expected = get_eligible_bits_of_nth_size(n, p);
    let mut packed = Integer::ZERO;

    for (i, part) in parts.iter().enumerate() {
        if part.significant_bits() > max_expected {
            panic!(
                "Part {part} exceeds the maximum expected bit length of {max_expected} for 1/{n} bit length of {p}."
            );
        }

        packed += part;

        if i < n as usize - 1 {
            packed <<= max_expected;
        }
    }

    packed
}

pub fn cantor_pairing_mod(a: &Integer, b: &Integer, p: &Integer) -> Integer {
    (Integer::from(2).invert(p).unwrap() * (a.clone() + b.clone()) * (a + b.clone() + Integer::ONE)
        + b)
        .modulo(p)
}
