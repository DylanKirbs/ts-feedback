use crate::ruleset::RuleMeta;
use serde_json::Value;

pub fn score_rule(rule: &RuleMeta, matches: &Vec<Value>) -> f64 {
    match rule.severity.as_str() {
        "error" => {
            if rule.fail_if_matches {
                if matches.is_empty() { 1.0 } else { 0.0 }
            } else {
                if matches.is_empty() { 1.0 } else { 0.0 }
            }
        }
        "warn" => {
            if let Some(max) = rule.params.get("max").and_then(|v| v.as_f64()) {
                let count = matches.len() as f64;
                if count <= max {
                    1.0
                } else {
                    (max / count).max(0.0)
                }
            } else {
                if matches.is_empty() { 1.0 } else { 0.5 }
            }
        }
        _ => 1.0, // info
    }
}
