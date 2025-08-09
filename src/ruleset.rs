use anyhow::Result;
use serde::Deserialize;
use std::fs;
use tree_sitter::{Language, Parser};

#[derive(Debug, Deserialize)]
pub struct RuleMeta {
    pub file: String,
    pub description: Option<String>,
    pub severity: String, // error, warn, info
    pub weight: Option<f64>,
    #[serde(default)]
    pub fail_if_matches: bool,
    #[serde(default)]
    pub params: serde_json::Value,
    #[serde(skip)]
    pub query_text: String,
}

#[derive(Debug, Deserialize)]
pub struct Ruleset {
    pub language: String,
    #[serde(skip)]
    pub id: String,
    pub rules: std::collections::HashMap<String, RuleMeta>,
}

impl Ruleset {
    pub fn load(dir: &str) -> Result<Self> {
        let yaml_path = format!("{}/rules.yaml", dir);

        if !std::path::Path::new(&yaml_path).exists() {
            anyhow::bail!("Ruleset file not found at {}", yaml_path);
        }
        if !std::path::Path::new(dir).is_dir() {
            anyhow::bail!("Ruleset directory does not exist: {}", dir);
        }

        let mut rs: Ruleset = serde_yaml::from_str(&fs::read_to_string(&yaml_path)?)?;
        rs.id = std::path::Path::new(dir)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();

        for (_name, rule) in rs.rules.iter_mut() {
            let qpath = format!("{}/{}", dir, rule.file);
            rule.query_text = fs::read_to_string(&qpath)?;
        }
        Ok(rs)
    }

    pub fn get_parser(&self) -> Result<Parser> {
        let mut parser = Parser::new();
        parser.set_language(&self.get_language()?)?;
        Ok(parser)
    }

    pub fn get_language(&self) -> Result<Language> {
        match self.language.as_str() {
            "c" => Ok(Language::new(tree_sitter_c::LANGUAGE)),
            _ => anyhow::bail!("Unsupported language {}", self.language),
        }
    }
}
