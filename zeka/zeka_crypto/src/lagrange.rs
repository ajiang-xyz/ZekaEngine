use rug::Integer;
use std::cmp::max;

pub fn generate_poly(x_s: &[Integer], y_s: &[Integer], p: &Integer) -> Vec<Integer> {
    assert!(
        x_s.len() == y_s.len(),
        "x_s (len {}) and y_s (len {}) must have the same length",
        x_s.len(),
        y_s.len()
    );

    // Polynomial must be of degree k - 1
    let k = x_s.len();
    let mut result = vec![Integer::ZERO; k];

    for i in 0..k {
        let mut numerator = vec![Integer::from(1)];
        let mut denominator = Integer::from(1);

        for j in 0..k {
            if j == i {
                continue;
            }

            // Product of x-x_j terms
            numerator = poly_mul_mod(&numerator, &[-x_s[j].clone(), Integer::from(1)], p);

            // Pre-inverse product of x_i-x_j terms
            denominator = (denominator * (x_s[i].clone() - x_s[j].clone()).modulo(p)).modulo(p);
        }

        // Complete the product
        let l_i = numerator
            .iter()
            .map(|coef| {
                (coef
                    * Integer::from(denominator.invert_ref(p).unwrap_or_else(|| panic!("Denominator ({denominator}) doesn't have an inverse! Maybe p ({p}) is not prime?"))))
                .modulo(p)
            })
            .collect::<Vec<Integer>>();

        // Add the basis polynomial to the result
        let basis = l_i
            .iter()
            .map(|coef| (coef * y_s[i].clone()).modulo(p))
            .collect::<Vec<Integer>>();

        result = poly_add_mod(&result, &basis, p);
    }

    result
}

pub fn evaluate_poly_at_mod(poly: &[Integer], x: &Integer, p: &Integer) -> Integer {
    if poly.len() == 1 {
        return poly[0].clone();
    }

    let mut result = poly[0].clone();

    for (i, coef) in poly.iter().enumerate().skip(1) {
        let exp = Integer::from(i);
        result = (result + coef * Integer::from(x.pow_mod_ref(&exp, p).unwrap())).modulo(p);
    }

    result
}

fn poly_mul_mod(poly1: &[Integer], poly2: &[Integer], p: &Integer) -> Vec<Integer> {
    let mut result = vec![Integer::ZERO; poly1.len() + poly2.len() - 1];

    for (i, a) in poly1.iter().enumerate() {
        for (j, b) in poly2.iter().enumerate() {
            result[i + j] = (result[i + j].clone() + a * b).modulo(p);
        }
    }

    result
}

fn poly_add_mod(poly1: &[Integer], poly2: &[Integer], p: &Integer) -> Vec<Integer> {
    let n = max(poly1.len(), poly2.len());
    let mut result = vec![Integer::ZERO; n];

    for i in 0..n {
        let a = if i < poly1.len() {
            &poly1[i]
        } else {
            &Integer::ZERO
        };

        let b = if i < poly2.len() {
            &poly2[i]
        } else {
            &Integer::ZERO
        };

        result[i] = Integer::from(a + b).modulo(p);
    }

    result
}

#[macro_export]
macro_rules! big_int {
    ($expr:literal) => {{
        let s = stringify!($expr);

        // Strip a leading and trailing quotes
        let digits = if (s.starts_with('"') && s.ends_with('"'))
            || (s.starts_with('\'') && s.ends_with('\''))
        {
            &s[1..s.len() - 1]
        } else {
            s
        };
        ::rug::Integer::from(
            ::rug::Integer::parse(digits).expect(concat!("Invalid decimal literal: ", $expr)),
        )
    }};
}

#[macro_export]
macro_rules! big_int_vec {
    ($($x:expr),+ $(,)?) => {{
        let mut temp_vec = Vec::<::rug::Integer>::new();

        $(
            temp_vec.push($crate::big_int![$x]);
        )*

        temp_vec
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts;

    #[test]
    fn test_poly_construction() {
        let x_s = big_int_vec![16, 32, 64];
        let y_s = big_int_vec![7, 8, 9];

        let poly = generate_poly(&x_s, &y_s, &consts::VULN_FIELD_MOD);

        let expected = big_int_vec![
            "32996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996633002",
            "52588383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838",
            "14758259680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680"
        ];

        assert_eq!(poly, expected)
    }

    #[test]
    fn test_poly_evaluation() {
        let poly = big_int_vec![
            "32996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996632996633002",
            "52588383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838383838",
            "14758259680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680134680"
        ];

        let x = big_int_vec![16, 32, 64, 69, 128, 255, 256];

        let expected = big_int_vec![
            "7",
            "8",
            "9",
            "79204808501683501683501683501683501683501683501683501683501683501683501683501683501683501683501683501683501683501683501683501683501683501683501683501683501683510",
            "7",
            "28163141835016835016835016835016835016835016835016835016835016835016835016835016835016835016835016835016835016835016835016835016835016835016835016835016835016822",
            "98989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898989898976",
        ];

        for (i, val) in x.iter().enumerate() {
            assert_eq!(
                evaluate_poly_at_mod(&poly, val, &consts::VULN_FIELD_MOD),
                expected[i]
            );
        }
    }
}
