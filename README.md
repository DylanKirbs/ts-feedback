# TS-FEEDBACK

A simple CLI tool to provide feedback on programming assignments using tree-sitter queries composed in a YAML file.

## Usage
```bash
cargo run -- <path_to_code_file> --ruleset <path_to_ruleset_directory>
```

## Example
```bash
cargo run -- examples/hello.c --ruleset rulesets/example
```

## Ruleset Structure

A ruleset consists of a directory containing:
- `rules.yaml` - Main configuration file
- Query files (`.scm`) - Tree-sitter queries for each rule

### Example `rules.yaml`
```yaml
language: c
rules:
  no-goto:
    file: queries/no-goto.scm
    description: "Disallow use of goto statements"
    severity: error
    weight: 5
    fail_if_matches: true

  max-function-length:
    file: queries/max-function-length.scm
    description: "Warn if function body exceeds 50 lines"
    severity: warn
    weight: 2
    params:
      max: 50
```

### Rule Properties
- `file`: Path to the tree-sitter query file (relative to ruleset directory)
- `description`: Human-readable description of the rule
- `severity`: `error`, `warn`, or `info`
- `weight`: Numeric weight for scoring (default: 1.0)
- `fail_if_matches`: If true, rule fails when query matches (default: false)
- `params`: Additional parameters (e.g., `max` for threshold-based rules)

### Example Query Files

**`queries/no-goto.scm`** (matches goto statements):
```scheme
(goto_statement) @goto
```

**`queries/max-function-length.scm`** (matches function bodies):
```scheme
(function_definition
  body: (compound_statement) @body)
```

### Scoring
- **Error rules**: Pass (1.0) or fail (0.0) based on `fail_if_matches`
- **Warn rules**: 
  - With `max` parameter: Score decreases proportionally when matches exceed threshold
  - Without `max`: Pass (1.0) for no matches, partial credit (0.5) for any matches
- **Info rules**: Always pass (1.0)

Final score is weighted average across all rules.
