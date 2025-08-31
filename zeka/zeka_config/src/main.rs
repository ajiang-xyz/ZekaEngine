use clap::Parser;
use rug::{Integer, rand::RandState};
use std::{
    fs::File,
    io::{Read, Write},
};
use zeka_config::encoder::{
    RawZekaConfigContainer, TransitionsBuilder, encode_expressions, parse_yaml_doc,
};
use zeka_crypto::{consts, lagrange::generate_poly, numbers::RugIntoBytes};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    // #[arg(short, long, default_value = "zeka/zeka_config/config.yaml")]
    #[arg(short, long)]
    config: String,

    #[arg(short, long, default_value = "zeka.dat")]
    out: String,
}

fn main() {
    let args = Args::parse();
    let mut rng = RandState::new();
    rng.seed(&Integer::from(consts::SEED));

    let mut builder = TransitionsBuilder::new(rng);

    if let Ok((metadata, exprs)) = parse_yaml_doc(args.config, &mut builder) {
        let _ = encode_expressions(&metadata, &exprs, &mut builder);
        println!("Parsed successfully:\n\n{metadata:#?}\n\n{exprs:#?}\n");

        let (x_s, y_s): (Vec<Integer>, Vec<Integer>) = builder.l1_transitions.into_iter().unzip();
        let l1 = generate_poly(x_s.as_slice(), y_s.as_slice(), &consts::VULN_FIELD_MOD);

        let (x_s, y_s): (Vec<Integer>, Vec<Integer>) = builder.l2_transitions.into_iter().unzip();
        let l2 = generate_poly(x_s.as_slice(), y_s.as_slice(), &consts::EXPR_FIELD_MOD);

        let (x_s, y_s): (Vec<Integer>, Vec<Integer>) = builder.l3_transitions.into_iter().unzip();
        let l3 = generate_poly(x_s.as_slice(), y_s.as_slice(), &consts::DFA_FIELD_MOD);

        let container = RawZekaConfigContainer {
            metadata,
            p_l1: consts::VULN_FIELD_MOD.to_bytes(),
            p_l2: consts::EXPR_FIELD_MOD.to_bytes(),
            p_l3: consts::DFA_FIELD_MOD.to_bytes(),
            var_max: consts::VAR_COMPONENT_MAX.to_bytes(),
            expr_max: consts::EXPR_COMPONENT_MAX.to_bytes(),
            l1: l1.iter().map(|x| x.to_bytes()).collect(),
            l2: l2.iter().map(|x| x.to_bytes()).collect(),
            l3: l3.iter().map(|x| x.to_bytes()).collect(),
        };

        let mut buf = vec![];
        ciborium::ser::into_writer(&container, &mut buf).expect("Unable to serialize.");

        let mut out =
            File::create(&args.out).unwrap_or_else(|_| panic!("Unable to create `{}`.", args.out));
        out.write_all(&buf)
            .unwrap_or_else(|_| panic!("Unable to write to `{}`.", args.out));

        let mut file =
            File::open(&args.out).unwrap_or_else(|_| panic!("Unable to open `{}`.", args.out));
        let mut contents = vec![];
        file.read_to_end(&mut contents)
            .unwrap_or_else(|_| panic!("Unable to read `{}`.", args.out));

        let _: RawZekaConfigContainer =
            ciborium::de::from_reader(contents.as_slice()).expect("Unable to deserialize.");

        println!("Wrote to `{}` successfully.", args.out);
    }
}
