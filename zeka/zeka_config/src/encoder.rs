use crate::checks::{self, RegexCheck, YamlError, ZekaCheck};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{AeadMutInPlace, KeyInit},
};
use ariadne::{Color, Label, Report, ReportKind, Source};
use hashlink::LinkedHashMap;
use rug::{Integer, integer::Order, rand::RandState};
use saphyr::{LoadableYamlNode, MarkedYaml, Marker, YamlData};
use saphyr_parser::Span;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fmt,
};
use zeka_crypto::{
    consts,
    dfa::InputClass,
    numbers::{
        RugIntoBytes, cantor_pairing_mod, generate_unique_flagless_point_mod,
        generate_unique_point_mod, get_parts_of_one_nth_size, pack_nth_parts_into_size,
    },
};

pub trait IntoAriadneSpan {
    fn into_range(&self) -> std::ops::Range<usize>;
}

impl IntoAriadneSpan for Span {
    fn into_range(&self) -> std::ops::Range<usize> {
        self.start.index()..self.end.index()
    }
}

pub struct TransitionsBuilder<'a> {
    pub rng: RandState<'a>,

    // Lagrange polynomial points
    pub l1_transitions: Vec<(Integer, Integer)>,
    pub l2_transitions: Vec<(Integer, Integer)>,
    pub l3_transitions: Vec<(Integer, Integer)>,

    pub states: HashSet<Integer>,
}

impl<'a> TransitionsBuilder<'a> {
    pub fn new(rng: RandState<'a>) -> Self {
        Self {
            rng,

            l1_transitions: Vec::new(),
            l2_transitions: Vec::new(),
            l3_transitions: Vec::new(),

            states: HashSet::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ZekaConfigMetadata {
    pub title: String,
    pub aead: Vec<u8>,
    pub remote_url: String,
    pub remote_password: String,
    pub is_local: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RawZekaConfigContainer {
    pub metadata: ZekaConfigMetadata,
    pub p_l1: Vec<u8>,
    pub p_l2: Vec<u8>,
    pub p_l3: Vec<u8>,
    pub var_max: Vec<u8>,
    pub expr_max: Vec<u8>,
    pub l1: Vec<Vec<u8>>,
    pub l2: Vec<Vec<u8>>,
    pub l3: Vec<Vec<u8>>,
}

impl RawZekaConfigContainer {
    pub fn into_config(self) -> ZekaConfigContainer {
        ZekaConfigContainer {
            metadata: self.metadata,
            p_l1: Integer::from_digits(&self.p_l1, Order::Lsf),
            p_l2: Integer::from_digits(&self.p_l2, Order::Lsf),
            p_l3: Integer::from_digits(&self.p_l3, Order::Lsf),
            var_max: Integer::from_digits(&self.var_max, Order::Lsf),
            expr_max: Integer::from_digits(&self.expr_max, Order::Lsf),
            l1: self
                .l1
                .into_iter()
                .map(|a| Integer::from_digits(a.as_slice(), Order::Lsf))
                .collect(),
            l2: self
                .l2
                .into_iter()
                .map(|a| Integer::from_digits(a.as_slice(), Order::Lsf))
                .collect(),
            l3: self
                .l3
                .into_iter()
                .map(|a| Integer::from_digits(a.as_slice(), Order::Lsf))
                .collect(),
        }
    }
}

#[derive(Debug)]
pub struct ZekaConfigContainer {
    pub metadata: ZekaConfigMetadata,
    pub p_l1: Integer,
    pub p_l2: Integer,
    pub p_l3: Integer,
    pub var_max: Integer,
    pub expr_max: Integer,
    pub l1: Vec<Integer>,
    pub l2: Vec<Integer>,
    pub l3: Vec<Integer>,
}

impl ZekaConfigMetadata {
    pub fn new() -> Self {
        Self {
            title: String::from("Training Round"),
            aead: consts::AEAD.to_vec(),
            remote_url: String::new(),
            remote_password: String::new(),
            is_local: true,
        }
    }
}

impl fmt::Debug for ZekaConfigMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZekaConfigMetadata")
            .field("aead", &format!("0x{}", &hex::encode(&self.aead)))
            .field("remote_url", &self.remote_url)
            .field("remote_password", &self.remote_password)
            .field("is_local", &self.is_local)
            .finish()
    }
}

pub fn yaml_node_to_check<'a>(
    node: MarkedYaml<'a>,
    builder: &mut TransitionsBuilder<'a>,
    errs: &mut Vec<YamlError>,
) -> Option<Box<dyn ZekaCheck<'a> + 'a>> {
    let key_node = node.data.as_mapping().unwrap().keys().next().unwrap();
    let (check_type, args) = parse_yaml_check(node.clone(), errs);

    let var_ident = generate_unique_flagless_point_mod(
        &mut builder.rng,
        &consts::EXPR_FIELD_MOD,
        &mut builder.states,
    );

    match check_type.as_str() {
        // "raw_regex" => Some(Box::new(RawRegexCheck { node, args })),
        "regex" => Some(Box::new(RegexCheck {
            node,
            args,
            var_ident,
        })),
        _ => {
            errs.push(YamlError {
                message: format!(
                    "Expected check type in {:?}, got {}.",
                    "[regex]", check_type
                ),
                err_type: "Invalid key".to_string(),
                span: key_node.span,
            });
            None
        }
    }
}

pub fn parse_yaml_doc<'a>(
    path: String,
    builder: &mut TransitionsBuilder<'a>,
) -> Result<
    (
        ZekaConfigMetadata,
        Vec<(
            String,
            Integer,
            Integer,
            Vec<(Integer, Integer, Box<dyn ZekaCheck<'a> + 'a>)>,
        )>,
    ),
    &'static str,
> {
    let src = std::fs::read_to_string(&path).unwrap();
    let mut errs: Vec<YamlError> = vec![];

    // Contains vectors of checks homogeneous to a sigle expression
    let mut expr_checks: Vec<(
        String,
        Integer,
        Integer,
        Vec<(Integer, Integer, Box<dyn ZekaCheck<'a> + 'a>)>,
    )> = vec![];

    let mut docs = MarkedYaml::load_from_str(&src).unwrap_or_else(|e| {
        let start = *e.marker();
        let end = Marker::new(start.index() + 1, start.line(), start.col() + 1);

        let mut c = e.info().chars();
        errs.push(YamlError {
            message: format!(
                "{}.",
                match c.next() {
                    Some(l) => l.to_uppercase().to_string() + c.as_str(),
                    None => "<unknown>".to_string(),
                }
            ),
            err_type: "Invalid YAML".to_string(),
            span: Span { start, end },
        });

        vec![MarkedYaml {
            span: Span::default(),
            data: YamlData::Sequence(vec![]),
        }]
    });

    let mut config_metadata = ZekaConfigMetadata::new();
    if docs.is_empty() || docs.len() > 2 {
        errs.push(YamlError {
            message: format!(
                "Expected exactly 1 or 2 YAML documents, got {}.",
                docs.len()
            ),
            err_type: "Invalid definition".to_string(),
            span: Span::default(),
        });
        docs = vec![];
    }

    if docs.len() == 2 {
        let metadata_doc = docs.remove(0);
        for obj in metadata_doc.data.as_vec().unwrap() {
            for (key, val) in obj.data.as_mapping().unwrap() {
                match key.data.as_str().unwrap_or_else(|| {
                    errs.push(YamlError {
                        message: format!("Expected metadata key as string, got {:?}.", key.data),
                        err_type: "Invalid key".to_string(),
                        span: key.span,
                    });
                    "<unknown>"
                }) {
                    "title" => {
                        if let Some(title) = val.data.as_str() {
                            config_metadata.title = title.to_string();
                        } else {
                            errs.push(YamlError {
                                message: format!("Expected aead as string, got {:?}.", val.data),
                                err_type: "Invalid definition".to_string(),
                                span: val.span,
                            });
                        }
                    }
                    "aead" => {
                        if let Some(aead) = val.data.as_str() {
                            config_metadata.aead = aead.as_bytes().to_vec();
                        } else {
                            errs.push(YamlError {
                                message: format!("Expected aead as string, got {:?}.", val.data),
                                err_type: "Invalid definition".to_string(),
                                span: val.span,
                            });
                        }
                    }
                    "seed" => {
                        if let Some(seed) = val.data.as_integer() {
                            // Don't actually save the seed to the config
                            builder.rng.seed(&Integer::from(seed));
                        } else {
                            errs.push(YamlError {
                                message: format!("Expected seed as integer, got {:?}.", val.data),
                                err_type: "Invalid definition".to_string(),
                                span: val.span,
                            });
                        }
                    }
                    "remote_url" => {
                        if let Some(url) = val.data.as_str() {
                            config_metadata.remote_url = url.to_string().clone();
                        } else {
                            errs.push(YamlError {
                                message: format!(
                                    "Expected remote_url as string, got {:?}.",
                                    val.data
                                ),
                                err_type: "Invalid definition".to_string(),
                                span: val.span,
                            });
                        }
                    }
                    "remote_password" => {
                        if let Some(password) = val.data.as_str() {
                            config_metadata.remote_password = password.to_string().clone();
                        } else {
                            errs.push(YamlError {
                                message: format!(
                                    "Expected remote_password as string, got {:?}.",
                                    val.data
                                ),
                                err_type: "Invalid definition".to_string(),
                                span: val.span,
                            });
                        }
                    }
                    "is_local" => {
                        if let Some(is_local) = val.data.as_bool() {
                            config_metadata.is_local = is_local;
                        } else {
                            errs.push(YamlError {
                                message: format!(
                                    "Expected is_local as boolean, got {:?}.",
                                    val.data
                                ),
                                err_type: "Invalid definition".to_string(),
                                span: val.span,
                            });
                        }
                    }
                    "<unknown>" => {}
                    _ => {
                        errs.push(YamlError {
                            message: format!(
                                "Expected metadata key in {:?}, got {:?}.",
                                vec!["aead", "seed", "remote_url", "remote_password", "is_local"],
                                key.data
                            ),
                            err_type: "Invalid definition".to_string(),
                            span: key.span,
                        });
                    }
                }
            }
        }
    }

    let doc = docs.first().unwrap();
    for check in doc.data.as_vec().unwrap() {
        if check.data.is_value() {
            continue;
        }

        let vuln_metadata = check
            .data
            .as_mapping()
            .unwrap()
            .iter()
            .filter(|(k, _)| {
                !["pass", "fail", "category"].contains(&k.data.as_str().unwrap_or_else(|| {
                    errs.push(YamlError {
                        message: format!("Unable to parse vuln msg as string, got `{:?}`.", k.data),
                        err_type: "Invalid key".to_string(),
                        span: k.span,
                    });

                    // The filter will ignore this key if it can't unwrap
                    "pass"
                }))
            })
            .collect::<Vec<_>>();

        if vuln_metadata.is_empty() {
            errs.push(YamlError {
                message: "No vulnerability metadata (<msg>: <pts>) found in check.".to_string(),
                err_type: "Invalid definition".to_string(),
                span: check.span,
            });
            continue;
        }

        if vuln_metadata.len() != 1 {
            errs.push(YamlError {
                message: format!(
                    "Expected exactly one vulnerability metadata (<msg>: <pts>), got {}.",
                    vuln_metadata.len()
                ),
                err_type: "Invalid definition".to_string(),
                span: check.span,
            });
            continue;
        }

        let (msg, pts) = vuln_metadata[0];
        let msg = msg.data.as_str().unwrap();
        let pts = pts
            .data
            .as_floating_point()
            .or_else(|| pts.data.as_integer().map(|i| i as f64))
            .unwrap_or_else(|| {
                errs.push(YamlError {
                    message: format!(
                        "Expected integer or floating point value, got `{:?}`.",
                        pts.data
                    ),
                    err_type: "Invalid definition".to_string(),
                    span: pts.span,
                });
                0.0
            });

        let mut vuln_text = format!("{msg} - {pts} pts");
        // Subtract 8 for the category byte
        let max_bytes = consts::VULN_FIELD_MOD.significant_bits() / 8 - 8;
        if vuln_text.len() > max_bytes as usize {
            errs.push(YamlError {
                message: format!(
                    "Expected vulnerability metadata (<msg>: <pts>) of {} chars or fewer, got {}.",
                    max_bytes - 5,
                    vuln_text.len() - 5,
                ),
                err_type: "Invalid definition".to_string(),
                span: check.span,
            });
            continue;
        }

        let empty_check = MarkedYaml {
            span: Span::default(),
            data: YamlData::Sequence(vec![]),
        };

        if let Some(value) = check.data.as_mapping_get("category") {
            match value {
                MarkedYaml {
                    data: YamlData::Value(cat_scalar),
                    ..
                } => {
                    if !cat_scalar.is_string() {
                        errs.push(YamlError {
                            message: format!("Expected string value, got `{:?}`.", cat_scalar),
                            err_type: "Invalid definition".to_string(),
                            span: value.span,
                        });
                    }

                    let category = cat_scalar.as_str().unwrap();
                    if !checks::CATEGORIES.contains(&category) {
                        errs.push(YamlError {
                            message: format!(
                                "Expected category in {:?}, got `{}`.",
                                checks::CATEGORIES,
                                category
                            ),
                            err_type: "Invalid definition".to_string(),
                            span: value.span,
                        });
                    } else {
                        vuln_text.insert(0, unsafe {
                            char::from_u32_unchecked(
                                checks::CATEGORIES
                                    .iter()
                                    .position(|&r| r == category)
                                    .unwrap() as u32,
                            )
                        });
                    }
                }
                _ => {
                    errs.push(YamlError {
                        message: "Expected string value, got something else.".to_string(),
                        err_type: "Invalid definition".to_string(),
                        span: value.span,
                    });
                }
            }
        } else {
            errs.push(YamlError {
                message: "Expected `category` key.".to_string(),
                err_type: "Invalid definition".to_string(),
                span: check.span,
            });
        }

        // TODO: "fail" checks are not implemented yet.
        let mut expr_transitions = vec![];
        let (start, end) = assign_yaml_transitions(
            check.data.as_mapping_get("pass").unwrap_or_else(|| {
                errs.push(YamlError {
                    message: "Expected `pass` key.".to_string(),
                    err_type: "Invalid definition".to_string(),
                    span: check.span,
                });
                &empty_check
            }),
            builder,
            &mut expr_transitions,
            &mut errs,
        );

        // println!("{msg} - {pts} pts");
        // println!("start: {start}, end: {end}");
        // for (from, to, check) in &expr_transitions {
        //     println!("{from} -> {to} upon {}", check.pretty(&mut errs));
        // }
        // println!();

        expr_checks.push((vuln_text, start, end, expr_transitions));
    }

    for err in &errs {
        Report::build(ReportKind::Error, (&path, err.span.into_range()))
            .with_config(ariadne::Config::new().with_index_type(ariadne::IndexType::Byte))
            .with_message(err.err_type.clone())
            .with_label(
                Label::new((&path, err.span.into_range()))
                    .with_message(err.message.to_string())
                    .with_color(Color::Red),
            )
            .finish()
            .print((&path, Source::from(&src)))
            .unwrap();
    }

    if !errs.is_empty() {
        Err("Errors found in YAML document.")
    } else {
        Ok((config_metadata, expr_checks))
    }
}

pub fn encode_expressions<'a>(
    metadata: &ZekaConfigMetadata,
    parsed_yaml: &Vec<(
        String,
        Integer,
        Integer,
        Vec<(Integer, Integer, Box<dyn ZekaCheck<'a> + 'a>)>,
    )>,
    builder: &mut TransitionsBuilder<'a>,
) -> Result<(), &'static str> {
    let mut var_1_metadatas = vec![];

    for (plaintext, expr_dfa_start1, expr_halting_state, checks) in parsed_yaml.iter() {
        let key: &Key<Aes256Gcm> = &Sha256::digest(expr_halting_state.to_bytes());
        let mut cipher = Aes256Gcm::new(key);
        let mut buffer = vec![];

        buffer.extend_from_slice(plaintext.as_bytes());
        let tag = cipher
            .encrypt_in_place_detached(
                Nonce::from_slice(&[0; 12]),
                metadata.aead.as_slice(),
                &mut buffer,
            )
            .expect("Failed to encrypt plaintext.");

        let ciphertext = Integer::from_digits(buffer.as_slice(), Order::Msf);
        builder.states.insert(ciphertext.clone());
        let vuln_text_ptr1 = generate_unique_point_mod(
            &mut builder.rng,
            &consts::EXPR_COMPONENT_MAX,
            &mut builder.states,
        );
        builder
            .l1_transitions
            .push((vuln_text_ptr1.clone(), ciphertext.clone()));

        let aes_gcm_tag = Integer::from_digits(tag.as_slice(), Order::Msf);
        builder.states.insert(aes_gcm_tag.clone());
        let aes_gcm_tag_ptr1 = generate_unique_point_mod(
            &mut builder.rng,
            &consts::EXPR_COMPONENT_MAX,
            &mut builder.states,
        );
        builder
            .l1_transitions
            .push((aes_gcm_tag_ptr1.clone(), aes_gcm_tag.clone()));

        let expr_dfa_start_ptr1 = generate_unique_point_mod(
            &mut builder.rng,
            &consts::EXPR_COMPONENT_MAX,
            &mut builder.states,
        );
        builder
            .l2_transitions
            .push((expr_dfa_start_ptr1.clone(), expr_dfa_start1.clone()));

        let next_test_ident_ptr1 = generate_unique_point_mod(
            &mut builder.rng,
            &consts::EXPR_COMPONENT_MAX,
            &mut builder.states,
        );

        let expr_1 = pack_nth_parts_into_size(
            vec![
                vuln_text_ptr1,
                aes_gcm_tag_ptr1,
                next_test_ident_ptr1.clone(),
                expr_dfa_start_ptr1,
            ],
            4,
            &consts::VAR_COMPONENT_MAX,
        );
        builder.states.insert(expr_1.clone());

        let mut next_test_ident1 = next_test_ident_ptr1.clone();
        for (i, (expr_from, expr_to, check)) in checks.iter().enumerate() {
            // Generate the regex transitions and the DFA's starting state pointer
            let mut dfa_transitions = vec![];
            let (check_dfa_start1, check_halting_state) =
                check.encode(&mut builder.rng, &mut builder.states, &mut dfa_transitions);
            let check_dfa_start_ptr1 = generate_unique_point_mod(
                &mut builder.rng,
                &consts::VAR_COMPONENT_MAX,
                &mut builder.states,
            );
            builder
                .l3_transitions
                .push((check_dfa_start_ptr1.clone(), check_dfa_start1.clone()));

            // Encode the regex DFA
            for (regex_from, regex_to, byte) in &dfa_transitions {
                match byte {
                    InputClass::Byte(b) => {
                        let from = cantor_pairing_mod(
                            regex_from,
                            &Integer::from(*b),
                            &consts::DFA_FIELD_MOD,
                        );
                        builder.states.insert(from.clone());
                        builder.l3_transitions.push((from, regex_to.clone()));
                    }
                    InputClass::Eoi => {
                        builder.states.insert(regex_from.clone());
                        builder
                            .l3_transitions
                            .push((regex_from.clone(), regex_to.clone()));
                        // println!(
                        //     "{regex_to} is an accepting state (halting is: {check_halting_state})"
                        // );
                    }
                }
            }

            // Encode this ident check's transition for expr_dfa
            builder.l2_transitions.push((
                cantor_pairing_mod(expr_from, &check_halting_state, &consts::EXPR_FIELD_MOD),
                expr_to.clone(),
            ));

            let next_var_ptr1 = generate_unique_flagless_point_mod(
                &mut builder.rng,
                &consts::VAR_COMPONENT_MAX,
                &mut builder.states,
            );

            let var_ident1 = check.get_var_ident();

            // Construct the "linked list" of var idents to be tested against expr_dfa (next_test_ident1 --> next_test_ident2 --> ...)
            let mut next_test_ident2 = var_ident1.clone();
            if i < checks.len() - 1 {
                // Set HAS_NEXT flag for next_test_ident2
                next_test_ident2.set_bit(consts::EXPR_FIELD_MOD.significant_bits() - 1, true);

                builder
                    .l2_transitions
                    .push((next_test_ident1.clone(), next_test_ident2.clone()));

                next_test_ident1 = next_test_ident2;
            } else {
                builder
                    .l2_transitions
                    .push((next_test_ident1.clone(), next_test_ident2.clone()));
            }

            let var_ident_ptr1 = generate_unique_point_mod(
                &mut builder.rng,
                &consts::VAR_COMPONENT_MAX,
                &mut builder.states,
            );
            builder
                .l2_transitions
                .push((var_ident_ptr1.clone(), var_ident1.clone()));

            // Construct var_1
            let var_1 = pack_nth_parts_into_size(
                vec![
                    next_var_ptr1.clone(),
                    expr_1.clone(),
                    var_ident_ptr1.clone(),
                    check_dfa_start_ptr1.clone(),
                ],
                4,
                &consts::VULN_FIELD_MOD,
            );

            println!(
                "plaintext: {}\nciphertext: {}\ntag: {}\nkey: {}\nvar_1: {}\nexpr_1: {}",
                plaintext,
                ciphertext,
                aes_gcm_tag,
                Integer::from_digits(key.as_slice(), Order::Msf),
                var_1,
                expr_1,
            );
            println!(
                "from: {expr_from}\nto: {expr_to}\nupon: {check_halting_state}\nvar_ident: {var_ident1}"
            );
            println!();

            var_1_metadatas.push((var_1, check));
        }
    }

    // Finally, construct the "linked list" of vars associated with the same path (next_var_ptr1 --> next_var_ptr2 --> ...)
    let mut unique_paths: HashMap<String, Vec<Integer>> = HashMap::new();

    for var_1_metadata in var_1_metadatas {
        let (var_1, check) = var_1_metadata;
        let path = check.get_path();
        unique_paths.entry(path).or_insert(vec![]).push(var_1);
    }

    for (path, checks) in unique_paths {
        let mut previous_linked_var = Integer::from_digits(path.as_bytes(), Order::Msf);
        for (i, var_1) in checks.iter().enumerate() {
            let mut linked_var_1 = var_1.clone();
            if i < checks.len() - 1 {
                // Set HAS_NEXT flag for next_var_ptr1
                linked_var_1.set_bit(consts::VAR_COMPONENT_MAX.significant_bits() * 4 - 1, true);
            }

            // Encode the transition for this var in the vuln DFA
            builder
                .l1_transitions
                .push((previous_linked_var.clone(), linked_var_1.clone()));

            previous_linked_var =
                get_parts_of_one_nth_size::<4>(&linked_var_1, &consts::VULN_FIELD_MOD)[0].clone();
        }
        println!();
    }

    Ok(())
}

// fn write_scoring_data<'a>(
//     builder: &mut TransitionsBuilder<'a>,
//     metadata: &ZekaConfigMetadata,
// ) -> Result<(), &'static str> {
//     todo!("write this function")
// }

pub fn parse_yaml_check(node: MarkedYaml<'_>, errs: &mut Vec<YamlError>) -> (String, Vec<String>) {
    let node_type = node.data.as_mapping().unwrap().keys().next().unwrap();
    let children = match node
        .data
        .as_mapping()
        .and_then(|m| m.get(node_type))
        .and_then(|v| v.data.as_sequence())
    {
        Some(seq) => seq,
        None => {
            errs.push(YamlError {
                message: "Expected arguments, got none.".to_string(),
                err_type: "Invalid arguments".to_string(),
                span: node_type.span,
            });
            &vec![]
        }
    };

    (
        node_type.data.as_str().unwrap().to_string(),
        children
            .iter()
            .map(|c| {
                if let Some(s) = c.data.as_str() {
                    s.to_string()
                } else if let Some(i) = c.data.as_integer() {
                    i.to_string()
                } else {
                    errs.push(YamlError {
                        message: format!(
                            "Expected string or integer argument, got `{:?}`.",
                            c.data
                        ),
                        err_type: "Invalid argument".to_string(),
                        span: c.span,
                    });
                    "".to_string()
                }
            })
            .collect::<Vec<_>>(),
    )
}

pub fn assign_yaml_transitions<'a>(
    nodes: &MarkedYaml<'a>,
    builder: &mut TransitionsBuilder<'a>,
    expr_transitions: &mut Vec<(Integer, Integer, Box<dyn ZekaCheck<'a> + 'a>)>,
    errs: &mut Vec<YamlError>,
) -> (Integer, Integer) {
    let start = generate_unique_point_mod(
        &mut builder.rng,
        &consts::EXPR_FIELD_MOD,
        &mut builder.states,
    );
    let end = generate_unique_point_mod(
        &mut builder.rng,
        &consts::EXPR_FIELD_MOD,
        &mut builder.states,
    );

    fn recurse<'a>(
        node: &MarkedYaml<'a>,
        start: &Integer,
        end: &Integer,
        builder: &mut TransitionsBuilder<'a>,
        expr_transitions: &mut Vec<(Integer, Integer, Box<dyn ZekaCheck<'a> + 'a>)>,
        errs: &mut Vec<YamlError>,
    ) {
        let empty_mapping: LinkedHashMap<MarkedYaml<'_>, MarkedYaml<'_>> = LinkedHashMap::new();
        let invalid_key = MarkedYaml::scalar_from_string("__ZEKA_INVALID__".to_string());
        let key_node = node
            .data
            .as_mapping()
            .unwrap_or_else(|| {
                errs.push(YamlError {
                    message: "Expected a mapping node.".to_string(),
                    err_type: "Invalid definition".to_string(),
                    span: node.span,
                });
                &empty_mapping
            })
            .keys()
            .next()
            .unwrap_or_else(|| {
                errs.push(YamlError {
                    message: "Expected a key in the mapping node.".to_string(),
                    err_type: "Invalid definition".to_string(),
                    span: node.span,
                });
                &invalid_key
            });

        if key_node.data == invalid_key.data {
            return;
        }

        if node.data.contains_mapping_key("and") {
            let mut current = start.clone();
            let children = node.data.as_mapping_get("and").unwrap().data.as_vec();
            if let Some(children) = children {
                if children.is_empty() {
                    errs.push(YamlError {
                        message: "Expected at least one argument, got 0.".to_string(),
                        err_type: "Invalid definition".to_string(),
                        span: key_node.span,
                    });
                    return;
                }
            } else {
                errs.push(YamlError {
                    message: format!("Expected an array of arguments, got {children:?}."),
                    err_type: "Invalid definition".to_string(),
                    span: key_node.span,
                });
                return;
            }

            let children = children.unwrap();
            for (i, child) in children.iter().enumerate() {
                let next = if i == children.len() - 1 {
                    end
                } else {
                    &generate_unique_point_mod(
                        &mut builder.rng,
                        &consts::EXPR_FIELD_MOD,
                        &mut builder.states,
                    )
                };

                recurse(child, &current, next, builder, expr_transitions, errs);
                current = next.clone();
            }
        } else if node.data.contains_mapping_key("or") {
            let children = node.data.as_mapping_get("or").unwrap().data.as_vec();
            if let Some(children) = children {
                if children.is_empty() {
                    errs.push(YamlError {
                        message: "Expected at least one argument, got 0.".to_string(),
                        err_type: "Invalid definition".to_string(),
                        span: key_node.span,
                    });
                    return;
                }
            } else {
                errs.push(YamlError {
                    message: format!("Expected an array of arguments, got {children:?}."),
                    err_type: "Invalid definition".to_string(),
                    span: key_node.span,
                });
                return;
            }

            let children = children.unwrap();

            for child in children {
                recurse(child, start, end, builder, expr_transitions, errs);
            }

            // Allow null transition if any of the transitions in the OR matched
            builder.l2_transitions.push((
                cantor_pairing_mod(&end, &Integer::ZERO, &consts::EXPR_FIELD_MOD),
                end.clone(),
            ));
            builder.l2_transitions.push((
                cantor_pairing_mod(&start, &Integer::ZERO, &consts::EXPR_FIELD_MOD),
                start.clone(),
            ));
        } else if let Some(check) = yaml_node_to_check(node.clone(), builder, errs) {
            if check.validate(errs) {
                expr_transitions.push((start.clone(), end.clone(), check));
            }
        }
    }

    // Impicit AND
    let children = nodes.data.as_vec().unwrap();
    let mut current = start.clone();
    for (i, node) in children.iter().enumerate() {
        let next = if i == children.len() - 1 {
            &end
        } else {
            &generate_unique_point_mod(
                &mut builder.rng,
                &consts::EXPR_FIELD_MOD,
                &mut builder.states,
            )
        };

        recurse(node, &current, next, builder, expr_transitions, errs);
        current = next.clone();
    }

    (start, end)
}

#[cfg(test)]
mod tests {
    use crate::checks::reduce_regex;

    #[test]
    fn test_yaml_errors() {}

    #[test]
    fn test_regex_reduction() {
        let regex = "  \\s*  the[\\t ]*\\tright\\s*answer  has\\s+many\\s*\\s+whitespaces    ";
        let reduced = reduce_regex(regex.to_string());
        assert_eq!(reduced, "^the right( )?answer has many whitespaces$");
    }
}
