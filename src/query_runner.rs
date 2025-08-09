use anyhow::Result;
use streaming_iterator::StreamingIterator;
use tree_sitter::{Language, Query, QueryCursor, Tree};

pub fn run_query(
    tree: &Tree,
    lang: &Language,
    query_text: &str,
    src: &str,
) -> Result<Vec<serde_json::Value>> {
    let query = Query::new(lang, query_text)?;
    let mut cursor = QueryCursor::new();
    let source_bytes = src.as_bytes();

    let mut results = Vec::new();

    let mut matches = cursor.matches(&query, tree.root_node(), source_bytes);
    while let Some(m) = matches.next() {
        for cap in m.captures {
            let node = cap.node;
            let start = node.start_position();
            let end = node.end_position();
            let snippet = &src[node.byte_range()];

            results.push(serde_json::json!({
                "capture": query.capture_names()[cap.index as usize],
                "start": [start.row, start.column],
                "end": [end.row, end.column],
                "snippet": snippet
            }));
        }
    }

    Ok(results)
}
