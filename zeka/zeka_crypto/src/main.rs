use rug::{Assign, Integer, integer::IsPrime, rand::RandState};
use sha2::{Digest, Sha256};
use zeka_crypto::{
    consts,
    numbers::{
        RugIntoBytes, generate_part_of_one_nth_size, generate_point_mod,
        get_eligible_bits_of_nth_size, get_mth_mask_of_nth_size, get_parts_of_one_nth_size,
    },
};

fn main() {
    let mut rng = RandState::new();
    rng.seed(&Integer::from(69422));

    println!(
        "VULN_FIELD_MOD: {} ({} bits)",
        consts::VULN_FIELD_MOD.clone(),
        consts::VULN_FIELD_MOD.significant_bits()
    );
    println!(
        "VAR_COMPONENT_MAX: {} ({} bits)",
        consts::VAR_COMPONENT_MAX.clone(),
        consts::VAR_COMPONENT_MAX.significant_bits()
    );
    println!(
        "EXPR_FIELD_MOD: {} ({} bits)",
        consts::EXPR_FIELD_MOD.clone(),
        consts::EXPR_FIELD_MOD.significant_bits()
    );
    println!(
        "EXPR_COMPONENT_MAX: {} ({} bits)",
        consts::EXPR_COMPONENT_MAX.clone(),
        consts::EXPR_COMPONENT_MAX.significant_bits()
    );
    println!(
        "DFA_FIELD_MOD: {} ({} bits)",
        consts::DFA_FIELD_MOD.clone(),
        consts::DFA_FIELD_MOD.significant_bits()
    );
    println!();

    let p = consts::VULN_FIELD_MOD.clone();
    let m = 2;
    let n = 4;

    println!(
        "Eligible bits of 1/{n} bit length of VULN_FIELD_MOD: {}",
        get_eligible_bits_of_nth_size(n, &p)
    );

    println!(
        "Random number of 1/{n} bit length of VULN_FIELD_MOD: {}",
        generate_part_of_one_nth_size(&mut rng, n, &p)
    );

    println!(
        "{m}th mask of 1/{n} bit length of VULN_FIELD_MOD: {}",
        get_mth_mask_of_nth_size(m, n, &p)
    );

    println!();

    let p = Integer::from(17);
    let mut n: Integer = Default::default();

    n.assign(generate_point_mod(&mut rng, &p));
    println!("Random n (mod {p}): {n}");
    assert!(n.significant_bits() <= 8);
    println!(
        "n^-1 (mod {p}): {}",
        n.clone()
            .invert(&p)
            .unwrap_or_else(|_| panic!("n doesn't have an inverse! Maybe p ({p}) is not prime?"))
    );
    let mut hasher = Sha256::new();
    hasher.update(n.to_bytes());
    let hash = hasher.finalize();
    println!("SHA256(n): {}", hex::encode(hash));

    for (name, p) in [
        ("VULN_FIELD_MOD", consts::VULN_FIELD_MOD.clone()),
        ("EXPR_FIELD_MOD", consts::EXPR_FIELD_MOD.clone()),
        ("DFA_FIELD_MOD", consts::DFA_FIELD_MOD.clone()),
    ] {
        if p.is_probably_prime(30) != IsPrime::Probably {
            println!("error: {name} ({p}) is not prime.");
        }
    }

    let x = "7128786886654554335839365008269049353030900975472727849556354646412978572438577293979656420374720659303432862253176290999811317524467678742416328279052954054543".parse::<Integer>().unwrap();
    let n = 4;
    let p = consts::VULN_FIELD_MOD.clone();
    println!(
        "get_of_one_nth_size({x}, {n}, {p}): {:?}",
        get_parts_of_one_nth_size::<4>(&x, &p)
    );
}
