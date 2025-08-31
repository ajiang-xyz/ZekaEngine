use crate::numbers::get_mth_mask_of_nth_size;
use rug::Integer;
use std::sync::LazyLock;

/////////////// MODIFIABLE VALUES ///////////////
pub const SEED: u64 = 7882829281509076855;
pub const AEAD: &[u8] = "zeka".as_bytes();

// L1
pub static VULN_FIELD_MOD: LazyLock<Integer> = LazyLock::new(|| {
    "98989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989"
        .parse::<Integer>()
        .unwrap()
});

// L2
pub static EXPR_FIELD_MOD: LazyLock<Integer> = LazyLock::new(|| {
    "79999999999999999999999999999999999999999999999999999999999999999999999999999"
        .parse::<Integer>()
        .unwrap()
});

// L3
pub static DFA_FIELD_MOD: LazyLock<Integer> = LazyLock::new(|| {
    "79999999999999999999999999999999999999999999999999999999999999999999999999999"
        .parse::<Integer>()
        .unwrap()
});
////////////////////// END //////////////////////

// Green box values; inclusive
pub static VAR_COMPONENT_MAX: LazyLock<Integer> =
    LazyLock::new(|| get_mth_mask_of_nth_size(4, 4, &VULN_FIELD_MOD));

// Pink box values; inclusive
pub static EXPR_COMPONENT_MAX: LazyLock<Integer> =
    LazyLock::new(|| get_mth_mask_of_nth_size(4, 4, &VAR_COMPONENT_MAX));
