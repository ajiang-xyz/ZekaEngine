use hashlink::LinkedHashMap;
use regex::Regex;
use regex_automata::dfa::sparse::DFA;
use rug::{Integer, rand::RandState};
use saphyr::{MarkedYaml, YamlData};
use saphyr_parser::Span;
use std::{collections::HashSet, fmt};
use zeka_crypto::{
    consts,
    dfa::{InputClass, parse_class_transitions},
};

pub const CATEGORIES: [&str; 13] = [
    "fq",
    "user_auditing",
    "account_policy",
    "local_policy",
    "defensive_countermeasure",
    "uncategorized",
    "service_auditing",
    "os_update",
    "app_update",
    "prohibited_file",
    "unwanted_software",
    "malware",
    "appsec",
];

#[derive(Debug)]
pub struct YamlError {
    pub message: String,
    pub err_type: String,
    pub span: Span,
}

pub trait ZekaCheck<'a>: ZekaCheckClone<'a> {
    fn validate(&self, errs: &mut Vec<YamlError>) -> bool;

    // Returns a tuple of (start, end) points for the DFA
    fn encode(
        &self,
        dfa_rng: &mut RandState,
        dfa_states: &mut HashSet<Integer>,
        dfa_transitions: &mut Vec<(Integer, Integer, InputClass)>,
    ) -> (Integer, Integer);

    fn pretty(&self, errs: &mut Vec<YamlError>) -> String;
    fn debug_fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result;

    fn get_path(&self) -> String;
    fn get_var_ident(&self) -> Integer;
}

pub trait ZekaCheckClone<'a> {
    fn clone_box(&self) -> Box<dyn ZekaCheck<'a> + 'a>;
}

impl<'a, T> ZekaCheckClone<'a> for T
where
    T: ZekaCheck<'a> + Clone + 'a,
{
    fn clone_box(&self) -> Box<dyn ZekaCheck<'a> + 'a> {
        Box::new(self.clone())
    }
}

impl<'a> Clone for Box<dyn ZekaCheck<'a> + 'a> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

impl<'a> fmt::Debug for dyn ZekaCheck<'a> + 'a {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.debug_fmt(f)
    }
}

///////////////////// CHECKS /////////////////////
#[derive(Clone)]
pub struct RawRegexCheck<'a> {
    pub node: MarkedYaml<'a>,
    pub args: Vec<String>,
    pub var_ident: Integer,
}

impl<'a> ZekaCheck<'a> for RawRegexCheck<'a> {
    fn validate(&self, errs: &mut Vec<YamlError>) -> bool {
        let key_node = self.node.data.as_mapping().unwrap().keys().next().unwrap();
        let mut path = self.args[0].clone();
        let regex = self.args[1].clone();

        if self.args.len() != 2 {
            errs.push(YamlError {
                message: format!(
                    "Expected exactly 2 arguments (<path>, <regex>), got {}.",
                    self.args.len()
                ),
                err_type: "Invalid arguments".to_string(),
                span: key_node.span,
            });
            return false;
        }

        path.retain(|c| !c.is_whitespace());

        if path.is_empty() {
            errs.push(YamlError {
                message: "Expected non-empty <path> in (<path>, <regex>).".to_string(),
                err_type: "Invalid argument".to_string(),
                span: key_node.span,
            });
            return false;
        }

        if regex.is_empty() {
            errs.push(YamlError {
                message: "Expected non-empty <regex> in (<path>, <regex>).".to_string(),
                err_type: "Invalid argument".to_string(),
                span: key_node.span,
            });
            return false;
        }

        true
    }

    fn encode(
        &self,
        dfa_rng: &mut RandState,
        dfa_states: &mut HashSet<Integer>,
        dfa_transitions: &mut Vec<(Integer, Integer, InputClass)>,
    ) -> (Integer, Integer) {
        let regex = self.args[1].clone();
        let dfa = DFA::new(&regex).unwrap();

        parse_class_transitions(
            &dfa,
            &consts::DFA_FIELD_MOD,
            dfa_rng,
            dfa_transitions,
            dfa_states,
        )
    }

    fn pretty(&self, errs: &mut Vec<YamlError>) -> String {
        if !self.validate(errs) {
            return "".to_string();
        }

        format!("raw_regex({:?})", self.args)
    }

    fn debug_fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawRegexCheck")
            .field("args", &self.args)
            .field("var_ident", &self.var_ident)
            .finish()
    }

    fn get_var_ident(&self) -> Integer {
        self.var_ident.clone()
    }

    fn get_path(&self) -> String {
        self.args[0].clone()
    }
}

#[derive(Clone)]
pub struct RegexCheck<'a> {
    pub node: MarkedYaml<'a>,
    pub args: Vec<String>,
    pub var_ident: Integer,
}
impl<'a> ZekaCheck<'a> for RegexCheck<'a> {
    fn validate(&self, errs: &mut Vec<YamlError>) -> bool {
        RawRegexCheck {
            node: self.node.clone(),
            args: self.args.clone(),
            var_ident: self.var_ident.clone(),
        }
        .validate(errs)
    }

    fn encode(
        &self,
        dfa_rng: &mut RandState,
        dfa_states: &mut HashSet<Integer>,
        dfa_transitions: &mut Vec<(Integer, Integer, InputClass)>,
    ) -> (Integer, Integer) {
        let path = self.args[0].clone();
        let regex = self.args[1].clone();

        let reduced = reduce_regex(regex);

        let mut reduced_check = LinkedHashMap::new();
        reduced_check.insert(
            MarkedYaml::scalar_from_string("raw_regex".to_string()),
            MarkedYaml {
                span: Span::default(),
                data: YamlData::Sequence(vec![
                    MarkedYaml::scalar_from_string(path.clone()),
                    MarkedYaml::scalar_from_string(reduced.clone()),
                ]),
            },
        );

        RawRegexCheck {
            node: MarkedYaml {
                span: Span::default(),
                data: YamlData::Mapping(reduced_check),
            },
            args: vec![path, reduced],
            var_ident: self.var_ident.clone(),
        }
        .encode(dfa_rng, dfa_states, dfa_transitions)
    }

    fn pretty(&self, errs: &mut Vec<YamlError>) -> String {
        if !self.validate(errs) {
            return "".to_string();
        }

        let path = self.args[0].clone();
        let regex = self.args[1].clone();
        let regex = reduce_regex(regex);

        format!("regex([{path}, {regex}])")
    }

    fn debug_fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegexCheck")
            .field("args", &self.args)
            .field("var_ident", &self.var_ident)
            .finish()
    }

    fn get_var_ident(&self) -> Integer {
        self.var_ident.clone()
    }

    fn get_path(&self) -> String {
        self.args[0].clone()
    }
}
////////////////////// END //////////////////////

pub fn reduce_regex(regex: String) -> String {
    let regex = regex.trim();
    let regex = regex.trim_start_matches('^').trim_end_matches('$');

    let leading_ws =
        Regex::new(r"^(\s*(\\s[\+\*\?]?|[ \t]+|[\[\(\\][^\]]+\][\+\*\?]?)*\s*)").unwrap();
    let trailing_ws =
        Regex::new(r"(\s*(\\s[\+\*\?]?|[ \t]+|[\[\(\\][^\]]+\][\+\*\?]?)*\s*)$").unwrap();

    let mut regex = leading_ws.replace(regex, "").to_string();
    regex = trailing_ws.replace(&regex, "").to_string();

    let ws = Regex::new(r"(\\s\*|\\s\+|\\s|\\t\*|\\t\+|\\t|[ \t]+|\[[^\]]+\][\*\+]?|\s+)").unwrap();

    // Tokenize whitespace patterns
    let mut tokens: Vec<String> = vec![];
    let mut last_end = 0;
    for m in ws.find_iter(&regex) {
        if m.start() > last_end {
            tokens.push(regex[last_end..m.start()].to_string());
        }

        tokens.push(if m.as_str().ends_with('*') {
            "__ZEKA_OPT_WS__".to_string()
        } else {
            "__ZEKA_REQ_WS__".to_string()
        });

        last_end = m.end();
    }

    if last_end < regex.len() {
        tokens.push(regex[last_end..].to_string());
    }

    // println!("tokens: {tokens:?}");

    // Normalize and reduce tokens
    let mut reduced = String::new();
    let mut i = 0;
    while i < tokens.len() {
        let curr = tokens[i].as_str();
        let next = tokens.get(i + 1).map(|s| s.as_str());
        match (curr, next) {
            ("__ZEKA_REQ_WS__", Some("__ZEKA_OPT_WS__"))
            | ("__ZEKA_REQ_WS__", Some("__ZEKA_REQ_WS__")) => {
                tokens.remove(i + 1);
            }
            ("__ZEKA_OPT_WS__", Some("__ZEKA_REQ_WS__"))
            | ("__ZEKA_OPT_WS__", Some("__ZEKA_OPT_WS__")) => {
                tokens.remove(i);
            }
            ("__ZEKA_REQ_WS__", Some(second)) => {
                reduced.push_str(format!(" {second}").as_str());
                i += 2;
            }
            ("__ZEKA_OPT_WS__", Some(second)) => {
                reduced.push_str(format!("( )?{second}").as_str());
                i += 2;
            }
            (first, Some("__ZEKA_REQ_WS__") | Some("__ZEKA_OPT_WS__") | None) => {
                reduced.push_str(first);
                i += 1;
            }
            (first, Some(second)) => {
                reduced.push_str(format!("{first}{second}").as_str());
                i += 2;
            }
        };
    }

    format!("^{reduced}$")
}
