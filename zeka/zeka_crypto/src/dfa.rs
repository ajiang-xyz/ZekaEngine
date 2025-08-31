use regex::Regex;
use regex_automata::{dfa::sparse::DFA, util::alphabet::Unit};
use rug::{Integer, rand::RandState};
use std::{
    collections::{BTreeSet, HashMap, HashSet, VecDeque},
    hash::Hash,
};

use crate::numbers::generate_point_mod;

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
enum EquivalenceClass {
    Byte(u8),
    Eoi,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum InputClass {
    Byte(u8),
    Eoi,
}

fn parse_byte(input: &str) -> u8 {
    // Handle stuff like ' '
    let s = if let (Some(_), Some(stripped)) = (input.strip_prefix('\''), input.strip_suffix('\''))
    {
        stripped
    } else {
        input
    };

    // Handle escapes
    match s {
        r"\n" => return b'\n',
        r"\r" => return b'\r',
        r"\t" => return b'\t',
        r"\0" => return 0,
        r"\\" => return b'\\',
        _ => {}
    }

    // Handle byte or single char
    if let Some(hex) = s.strip_prefix(r"\x") {
        u8::from_str_radix(hex, 16).unwrap()
    } else {
        // println!("Parsing byte: {s:?}");
        s.chars()
            .next()
            .expect("Whoa! Your regex crashed the engine!") as u8
    }
}

pub fn parse_class_transitions(
    dfa: &DFA<Vec<u8>>,
    p: &Integer,
    dfa_rng: &mut RandState,
    dfa_transitions: &mut Vec<(Integer, Integer, InputClass)>,
    dfa_states: &mut HashSet<Integer>,
) -> (Integer, Integer) {
    // Build the transition table from the DFA
    let string = format!("{dfa:#?}");

    let mut accepting_state: usize = 0;
    let re_line = Regex::new(r"^.*?(?P<state>\d+):\s*(?P<transitions>.+)$").unwrap();
    let re_transition =
        Regex::new(r"(?P<bytes>.+?(?:-.+?)?|EOI)\s*=>\s*(?P<next>\d+),?\s*").unwrap();

    let mut class_transitions: Vec<(usize, usize, EquivalenceClass)> = vec![];
    let mut adjacents: HashMap<usize, Vec<usize>> = HashMap::new();

    for line in string.lines().skip(1) {
        if line.is_empty() {
            break;
        }

        if let Some(captures) = re_line.captures(line) {
            let from = captures["state"].parse().unwrap();
            let transitions = &captures["transitions"];

            if line.contains('*') {
                accepting_state = from;
            }

            for transitions in re_transition.captures_iter(transitions) {
                let bytes = &transitions["bytes"];
                let next = transitions["next"].parse().unwrap();

                match bytes {
                    "EOI" => {
                        class_transitions.push((from, next, EquivalenceClass::Eoi));
                    }
                    s if s.contains('-') => {
                        let mut parts = s.split('-');
                        let start = parse_byte(parts.next().unwrap());
                        let end = parse_byte(parts.next().unwrap());
                        for b in start..=end {
                            class_transitions.push((from, next, EquivalenceClass::Byte(b)));
                        }
                    }
                    s => {
                        let b = parse_byte(s);
                        class_transitions.push((from, next, EquivalenceClass::Byte(b)));
                    }
                }

                adjacents.entry(from).or_default().push(next);
            }
        }
    }

    // Prune unreachable states
    let mut reachable: BTreeSet<usize> = BTreeSet::new();
    let mut queue: VecDeque<usize> = VecDeque::new();

    reachable.insert(35);
    queue.push_back(35);

    while let Some(state) = queue.pop_front() {
        for &next in adjacents.get(&state).into_iter().flatten() {
            if reachable.insert(next) {
                queue.push_back(next);
            }
        }
    }

    class_transitions.retain(|(from, _, _)| reachable.contains(from));

    // Randomize state IDs
    let mut id_mapping: HashMap<usize, Integer> = HashMap::new();

    let mut states = reachable.iter();
    while id_mapping.len() < reachable.len() {
        let id = generate_point_mod(dfa_rng, p);

        if dfa_states.insert(id.clone()) {
            let next = states.next().unwrap();
            id_mapping.insert(*next, id);
        }
    }

    // Translate equivalence classes to individual bytes
    let byte_classes = dfa.byte_classes();

    for (from, to, class) in class_transitions.iter() {
        let from_id = id_mapping[from].clone();
        let to_id = id_mapping[to].clone();

        match class {
            EquivalenceClass::Byte(b) => {
                for element in byte_classes.elements(Unit::u8(b.to_owned())) {
                    dfa_transitions.push((
                        from_id.clone(),
                        to_id.clone(),
                        InputClass::Byte(element.as_u8().unwrap()),
                    ));
                }
            }
            EquivalenceClass::Eoi => {
                dfa_transitions.push((from_id, to_id, InputClass::Eoi));
            }
        }
    }

    (
        id_mapping[&35].clone(),
        id_mapping[&accepting_state].clone(),
    )
}

pub fn walk_transitions(
    dfa_transitions: &[(Integer, Integer, InputClass)],
    start: &Integer,
    end: &Integer,
    haystack: &str,
) -> bool {
    let mut state = start.clone();
    for &b in haystack.as_bytes() {
        if let Some((_, to, _)) = dfa_transitions
            .iter()
            .find(|(from, _, input)| *from == state && *input == InputClass::Byte(b))
        {
            state = to.clone();
        } else {
            // println!("Uh oh, {b} is not a key!");
        }
    }

    if let Some((_, to, _)) = dfa_transitions
        .iter()
        .find(|(from, _, input)| *from == state && *input == InputClass::Eoi)
    {
        state = to.clone();
    }

    state == *end
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts;

    #[test]
    fn test_transitions_construction() {
        let pattern = r"^ANSWER:\s+(?i)hello(?-i)\s+World!\s*$";

        let dfa = DFA::new(pattern).unwrap();
        let mut dfa_rng = RandState::new();
        dfa_rng.seed(&Integer::from(consts::SEED));

        let mut dfa_states = HashSet::new();
        let mut dfa_transitions: Vec<(Integer, Integer, InputClass)> = vec![];

        let (start, end) = parse_class_transitions(
            &dfa,
            &consts::DFA_FIELD_MOD,
            &mut dfa_rng,
            &mut dfa_transitions,
            &mut dfa_states,
        );

        let length = dfa_transitions.len();
        println!("start: {start}, end: {end} ({} transitions)", length);

        assert_eq!(length, 491);
        assert!(walk_transitions(
            &dfa_transitions,
            &start,
            &end,
            r"ANSWER:       HelLo World!"
        ));
        assert!(!walk_transitions(
            &dfa_transitions,
            &start,
            &end,
            r"ANSWER:       HelLo world!"
        ));
        assert!(!walk_transitions(
            &dfa_transitions,
            &start,
            &end,
            r"ANSWER: HelLo world!          "
        ));
    }

    #[test]
    fn test_transitions_construction2() {
        let pattern = r"^hello$";

        let dfa = DFA::new(pattern).unwrap();
        let mut dfa_rng = RandState::new();
        dfa_rng.seed(&Integer::from(consts::SEED));

        let mut dfa_states = HashSet::new();
        let mut dfa_transitions: Vec<(Integer, Integer, InputClass)> = vec![];

        let (start, end) = parse_class_transitions(
            &dfa,
            &consts::DFA_FIELD_MOD,
            &mut dfa_rng,
            &mut dfa_transitions,
            &mut dfa_states,
        );

        println!("{dfa_transitions:#?}");

        println!(
            "start: {start}, end: {end} ({} transitions)",
            dfa_transitions.len()
        );

        assert!(!walk_transitions(
            &dfa_transitions,
            &start,
            &end,
            r"ANSWER:       HelLo World!"
        ));
        assert!(walk_transitions(
            &dfa_transitions,
            &start,
            &end,
            r"ANSWER:       hello world!"
        ));
        assert!(walk_transitions(&dfa_transitions, &start, &end, r"hello"));
    }
}
