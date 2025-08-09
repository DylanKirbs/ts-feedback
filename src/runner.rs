use crate::query_runner::run_query;
use crate::ruleset::Ruleset;
use crate::scoring::score_rule;
use anyhow::Result;
use std::fs;

pub fn run_file(path: &str, ruleset_dir: &str) -> Result<serde_json::Value> {
    let ruleset = Ruleset::load(ruleset_dir)?;
    let src = fs::read_to_string(path)?;
    let language_name = ruleset.language.clone();

    let mut parser = ruleset.get_parser()?;
    let tree = parser
        .parse(&src, None)
        .ok_or_else(|| anyhow::anyhow!("Parse failed"))?;
    let lang = ruleset.get_language()?;

    let mut out_rules = serde_json::Map::new();
    let mut total_weight = 0.0;
    let mut total_score = 0.0;

    for (name, rule) in &ruleset.rules {
        let matches = run_query(&tree, &lang, &rule.query_text, &src)?;
        let score = score_rule(rule, &matches);
        let weight = rule.weight.unwrap_or(1.0);

        total_weight += weight;
        total_score += score * weight;

        let json_matches: Vec<_> = matches.iter().map(|m| serde_json::json!(m)).collect();

        out_rules.insert(
            name.clone(),
            serde_json::json!({
                "matches": json_matches,
                "result": if score == 1.0 { "pass" } else if score > 0.0 { "warn" } else { "fail" },
                "weight": weight,
                "score": score
            }),
        );
    }

    let overall = if total_weight > 0.0 {
        total_score / total_weight
    } else {
        1.0
    };

    Ok(serde_json::json!({
        "file": path,
        "language": language_name,
        "ruleset": ruleset.id,
        "rules": out_rules,
        "aggregated": {
            "total_weight": total_weight,
            "score": overall
        }
    }))
}
