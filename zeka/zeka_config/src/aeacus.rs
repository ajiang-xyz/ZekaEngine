use serde::Deserialize;
use std::fs;
use std::path::Path;
use structopt::StructOpt;

#[derive(Deserialize, Debug)]
pub struct Condition {
    #[serde(rename = "type")]
    pub cond_type: String,
    pub path: Option<String>,
    pub cmd: Option<String>,
    pub user: Option<String>,
    pub group: Option<String>,
    pub name: Option<String>,
    pub key: Option<String>,
    pub value: Option<String>,
    pub after: Option<String>,
    pub regex: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct Check {
    pub message: Option<String>,
    pub points: Option<i64>,
    #[serde(rename = "pass")]
    pub pass_conditions: Option<Vec<Condition>>,
    #[serde(rename = "fail")]
    pub fail_conditions: Option<Vec<Condition>>,
    #[serde(rename = "passoverride")]
    pub passoverride_conditions: Option<Vec<Condition>>,
}

#[derive(Deserialize, Debug)]
pub struct AeacusConfig {
    pub name: String,
    pub title: String,
    pub os: String,
    pub user: String,
    pub version: String,
    #[serde(rename = "check")]
    pub checks: Option<Vec<Check>>,
    pub remote: Option<String>,
}

#[derive(StructOpt, Debug)]
#[structopt(name = "zeka_config")]
pub struct AeacusOpt {
    #[structopt(parse(from_os_str))]
    pub config: std::path::PathBuf,
}

pub fn parse_aeacus_config(path: &Path) -> Result<AeacusConfig, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(path)?;
    let cfg: AeacusConfig = toml::from_str(&content)?;
    Ok(cfg)
}
