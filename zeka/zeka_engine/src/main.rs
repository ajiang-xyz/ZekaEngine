use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, Tag, aead::AeadMutInPlace};
use chrono::Utc;
use itertools::Itertools;
use minijinja::{Environment, context};
use notify_rust::Notification;
use regex::Regex;
use rug::{Integer, integer::Order};
use serde::Serialize;
use sha2::{Digest, Sha256};
use spinners::{Spinner, Spinners};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, read_to_string},
    hash::{DefaultHasher, Hash, Hasher},
    io::Read,
    mem::take,
    sync::mpsc::{Receiver, Sender, TryRecvError, channel},
    thread,
    time::{Duration, Instant},
};
use zeka_config::encoder::RawZekaConfigContainer;
use zeka_crypto::{
    lagrange::evaluate_poly_at_mod,
    numbers::{RugIntoBytes, cantor_pairing_mod, get_parts_of_one_nth_size},
};
use zeka_engine::{
    providers::{ZekaEventMetadata, ZekaEventOrigin},
    report,
};

#[derive(Serialize, Debug)]
#[serde(untagged)]
enum Num {
    Int(i64),
    Float(f64),
}

#[derive(Serialize, Debug)]
struct Vuln {
    desc: String,
    points: Num,
}

fn hash_vec<T: Hash>(vec: &[T]) -> u64 {
    let mut hasher = DefaultHasher::new();
    vec.hash(&mut hasher);
    hasher.finish()
}

pub fn main() {
    let interval = 120;

    #[cfg(debug_assertions)]
    let interval = 1;

    let (event_tx1, event_rx): (
        Sender<(String, ZekaEventMetadata)>,
        Receiver<(String, ZekaEventMetadata)>,
    ) = channel();
    let (set_tx, set_rx): (
        Sender<HashMap<String, ZekaEventMetadata>>,
        Receiver<HashMap<String, ZekaEventMetadata>>,
    ) = channel();

    let mut file = File::open("zeka.dat").expect("Unable to open `zeka.dat`.");
    let mut contents = vec![];
    file.read_to_end(&mut contents)
        .unwrap_or_else(|_| panic!("Unable to read `zeka.dat`."));
    let container = ciborium::de::from_reader::<RawZekaConfigContainer, &[u8]>(contents.as_slice())
        .expect("Unable to deserialize.")
        .into_config();

    let mut env = Environment::new();
    env.add_template("report", report::REPORT_TEMPLATE).unwrap();
    let tmpl = env.get_template("report").unwrap();

    #[cfg(windows)]
    {
        use zeka_engine::providers::etw_provider;
        use zeka_engine::providers::registry_provider;
        let event_tx2 = event_tx1.clone();
        let event_tx3 = event_tx1.clone();
        thread::spawn(move || {
            etw_provider(event_tx2);
        });
        thread::spawn(move || {
            registry_provider(event_tx3);
        });
    };

    #[cfg(target_os = "linux")]
    {
        use zeka_engine::providers::fanotify_provider;
        thread::spawn(move || {
            fanotify_provider(event_tx1);
        });
    };

    // Event collector at scoring interval
    thread::spawn(move || {
        let interval = std::time::Duration::from_secs(interval);
        let mut event_map = HashMap::new();
        let mut then = Instant::now();

        loop {
            let now = Instant::now();

            if Instant::now() - then > interval {
                let moved_set = take(&mut event_map);
                match set_tx.send(moved_set) {
                    Ok(()) => {}
                    Err(e) => eprintln!("\rFailed sending event set: {e}"),
                }
                then = now;
            }

            match event_rx.try_recv() {
                Ok(event) => {
                    // Only keep the most recent state of any given file path
                    event_map.insert(event.0, event.1);
                }
                Err(e) => match e {
                    TryRecvError::Empty => thread::sleep(Duration::from_secs(1)),
                    TryRecvError::Disconnected => {
                        eprintln!("\rThe receiver closed.");
                        break;
                    }
                },
            }
        }
    });

    // Event processor
    let mut event_id = Integer::from(1);
    let mut check_id = Integer::from(1);
    let mut timestamp = "<never>".to_string();
    let ws = Regex::new(r"\s+").unwrap();
    let mut ident_eval_stack = HashSet::new();
    let mut saved_vars: HashMap<Integer, HashSet<Integer>> = HashMap::new();

    let mut scored_vulns = Vec::new();
    let mut old_hash = hash_vec(&scored_vulns);

    let mut sp = Spinner::new(Spinners::Dots, format!("Check {check_id} ({timestamp})"));
    loop {
        scored_vulns = Vec::new();

        match set_rx.recv() {
            Ok(event_set) => {
                sp.stop();
                sp = Spinner::new(Spinners::Dots, format!("Check {check_id} ({timestamp})"));
                check_id += 1;

                for (path, metadata) in event_set {
                    #[cfg(debug_assertions)]
                    {
                        if path.contains("zeka") && path.contains("report.html") {
                            continue;
                        }
                        println!("\revent {event_id}: path: {path} metadata: {metadata:?}");
                    }
                    event_id += 1;

                    // Actual engine logic
                    match metadata.origin {
                        ZekaEventOrigin::Etw | ZekaEventOrigin::Fanotify => {
                            let mut var_stack = vec![evaluate_poly_at_mod(
                                &container.l1,
                                &Integer::from_digits(path.as_bytes(), Order::Msf),
                                &container.p_l1,
                            )];

                            let file_content = read_to_string(&path).unwrap_or("".to_string());

                            while !var_stack.is_empty() {
                                let var_1 = var_stack.pop().unwrap();
                                let [next_var_ptr1, expr_1, var_ident_ptr1, check_dfa_start_ptr1] =
                                    &get_parts_of_one_nth_size::<4>(&var_1, &container.p_l1);

                                // Traverse the "next_var_ptr linked list"
                                if next_var_ptr1.significant_bits()
                                    == container.var_max.significant_bits()
                                {
                                    var_stack.push(evaluate_poly_at_mod(
                                        &container.l1,
                                        next_var_ptr1,
                                        &container.p_l1,
                                    ))
                                }

                                let [
                                    vuln_text_ptr1,
                                    aes_gcm_tag_ptr1,
                                    next_test_ident_ptr1,
                                    expr_dfa_start_ptr1,
                                ] = &get_parts_of_one_nth_size::<4>(expr_1, &container.var_max);

                                let ciphertext = evaluate_poly_at_mod(
                                    &container.l1,
                                    vuln_text_ptr1,
                                    &container.p_l1,
                                );

                                let aes_gcm_tag = evaluate_poly_at_mod(
                                    &container.l1,
                                    aes_gcm_tag_ptr1,
                                    &container.p_l1,
                                );

                                let expr_dfa_start1 = evaluate_poly_at_mod(
                                    &container.l2,
                                    expr_dfa_start_ptr1,
                                    &container.p_l2,
                                );

                                ident_eval_stack.insert((
                                    ciphertext,
                                    aes_gcm_tag,
                                    expr_dfa_start1,
                                    // next_test_ident1
                                    evaluate_poly_at_mod(
                                        &container.l2,
                                        next_test_ident_ptr1,
                                        &container.p_l2,
                                    ),
                                ));

                                let var_ident1 = evaluate_poly_at_mod(
                                    &container.l2,
                                    var_ident_ptr1,
                                    &container.p_l2,
                                );

                                let check_dfa_state = evaluate_poly_at_mod(
                                    &container.l3,
                                    check_dfa_start_ptr1,
                                    &container.p_l3,
                                );

                                // Clear seen vars
                                saved_vars
                                    .entry(var_ident1.clone())
                                    .and_modify(|v| {
                                        v.clear();
                                        v.insert(Integer::ZERO);
                                    })
                                    .or_insert(HashSet::from([Integer::ZERO]));

                                // Traverse all the regex DFAs before we traverse any of the expression DFAs
                                for line in file_content.lines().collect::<HashSet<_>>() {
                                    let stripped = ws.replace(line.trim(), " ").to_string();
                                    let mut current_state = check_dfa_state.clone();

                                    for c in stripped.chars() {
                                        current_state = evaluate_poly_at_mod(
                                            &container.l3,
                                            &cantor_pairing_mod(
                                                &current_state,
                                                &Integer::from(c as u64),
                                                &container.p_l3,
                                            ),
                                            &container.p_l3,
                                        );
                                    }
                                    current_state = evaluate_poly_at_mod(
                                        &container.l3,
                                        &current_state,
                                        &container.p_l3,
                                    );

                                    saved_vars
                                        .entry(var_ident1.clone())
                                        .or_insert(HashSet::from([Integer::ZERO]))
                                        .insert(current_state.clone());
                                    // println!(
                                    //     "\rsaved_vars: {saved_vars:?} (var_ident1: {var_ident1:?}, var_ident_ptr1: {var_ident_ptr1:?})"
                                    // );
                                    // println!("\r    {stripped}");
                                    // println!();
                                }
                            }
                        }
                        ZekaEventOrigin::Registry => {
                            // println!("\rNot implemented yet");
                        }
                    }
                }

                // Evaluate all of the expression DFAs
                for (ciphertext, aes_gcm_tag, expr_dfa_state, ident) in &ident_eval_stack {
                    let zero_set = HashSet::from([Integer::ZERO]);
                    // let (ciphertext, aes_gcm_tag, expr_dfa_state, mut ident) =
                    //     ident_eval_stack.pop().unwrap();
                    let mut tag_buffer = aes_gcm_tag
                        .to_bytes()
                        .into_iter()
                        .rev()
                        .take(16)
                        .collect::<Vec<_>>();
                    tag_buffer.resize(16, 0);

                    // let aes_gcm_tag = Integer::from_digits(tag_buffer.as_slice(), Order::Msf);
                    // println!(
                    //     "\rciphertext: {ciphertext}\naes_gcm_tag: {aes_gcm_tag}\nexpr_dfa_state: {expr_dfa_state}\nident: {ident}"
                    // );

                    let mut expr_dfa_stack = vec![];
                    let mut current_ident = ident.clone();
                    loop {
                        if current_ident.significant_bits() == container.p_l2.significant_bits() {
                            let mut next_ident = current_ident.clone();
                            next_ident.set_bit(current_ident.significant_bits() - 1, false);
                            // println!("\rPushing ident: {next_ident}");
                            expr_dfa_stack.push(saved_vars.get(&next_ident).unwrap_or(&zero_set));
                            current_ident = evaluate_poly_at_mod(
                                &container.l2,
                                &current_ident,
                                &container.p_l2,
                            );
                        } else {
                            // println!("\rPushing ident: {ident}");
                            expr_dfa_stack
                                .push(saved_vars.get(&current_ident).unwrap_or(&zero_set));
                            break;
                        }
                    }

                    // // Great for debugging lol
                    // println!();
                    // println!("\rsaved_vars: {saved_vars:?} (ident: {ident})");
                    // println!("\rexpr_dfa_stack: {expr_dfa_stack:?} (ident: {ident})");

                    for ident_vals in expr_dfa_stack
                        .into_iter()
                        .map(|v| v.into_iter())
                        .multi_cartesian_product()
                    {
                        let mut state = expr_dfa_state.clone();
                        for ident_val in ident_vals {
                            state = evaluate_poly_at_mod(
                                &container.l2,
                                &cantor_pairing_mod(&state, ident_val, &container.p_l2),
                                &container.p_l2,
                            );
                        }

                        let key: &Key<Aes256Gcm> = &Sha256::digest(state.to_bytes());
                        let mut cipher = Aes256Gcm::new(key);
                        let mut plain_buffer = vec![];

                        // println!(
                        //     "\rFinal state: {state} (key: {}, aead: {}, tag: {})",
                        //     Integer::from_digits(key.as_slice(), Order::Msf),
                        //     Integer::from_digits(container.metadata.aead.as_slice(), Order::Msf),
                        //     aes_gcm_tag
                        // );
                        plain_buffer.extend_from_slice(
                            ciphertext
                                .to_bytes()
                                .into_iter()
                                .rev()
                                .collect::<Vec<_>>()
                                .as_slice(),
                        );
                        // match cipher.decrypt_in_place_detached(
                        //     Nonce::from_slice(&[0; 12]),
                        //     &container.metadata.aead.as_slice(),
                        //     &mut plain_buffer,
                        //     Tag::from_slice(tag_buffer.as_slice()),
                        // ) {
                        //     Ok(()) => {
                        //         break;
                        //     }
                        //     Err(e) => {
                        //         println!("\rerror: {e}");
                        //     }
                        // }
                        if let Ok(()) = cipher.decrypt_in_place_detached(
                            Nonce::from_slice(&[0; 12]),
                            &container.metadata.aead.as_slice(),
                            &mut plain_buffer,
                            Tag::from_slice(tag_buffer.as_slice()),
                        ) {
                            scored_vulns
                                .push(unsafe { String::from_utf8_unchecked(plain_buffer.clone()) });
                            scored_vulns.sort();
                        }
                    }
                }

                timestamp = Utc::now().format("%m/%d/%Y %H:%M:%S UTC").to_string();
                let title = container.metadata.title.clone();
                let mut total = 0.0;
                let vulns = scored_vulns
                    .iter()
                    .map(|vuln| {
                        let (msg, pts) = vuln.split_once(" - ").unwrap();
                        let pts = pts
                            .trim()
                            .trim_end_matches(|c: char| c.is_ascii_alphabetic())
                            .trim();
                        let pts = if let Ok(i) = pts.parse::<i64>() {
                            total += i as f64;
                            Num::Int(i)
                        } else {
                            let i = pts.parse::<f64>().unwrap();
                            total += i;
                            Num::Float(i)
                        };
                        Vuln {
                            desc: msg[1..].to_string(),
                            points: pts,
                        }
                    })
                    .collect::<Vec<_>>();
                let out = tmpl
                    .render(context! { title => title, timestamp => timestamp, total => format!("{}", total), vulns => vulns })
                    .unwrap();
                fs::write("report.html", out).unwrap();

                let new_hash = hash_vec(&scored_vulns);
                if new_hash != old_hash {
                    if let Err(_) = Notification::new()
                        .summary("Notice")
                        .body("Your ZekaEngine scoring report has been updated!")
                        .show()
                    {
                        println!("\rYour scoring report has been updated!")
                    }

                    #[cfg(debug_assertions)]
                    {
                        println!("\rVulnerabilities: {scored_vulns:#?}\n");
                    }
                    old_hash = new_hash;
                };
            }
            Err(_) => {
                eprintln!("\rThe receiver closed.");
                break;
            }
        }
    }

    sp.stop();
}
