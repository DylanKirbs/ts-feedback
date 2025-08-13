#!/usr/bin/env python3
import argparse
import json
import yaml
import sys
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from tree_sitter import Language, Parser, Query, Node, QueryCursor

class Severity(Enum):
    INFO = "info"
    WARN = "warn"
    ERROR = "error"

@dataclass
class RuleResult:
    rule_name: str
    description: str
    severity: Severity
    weight: int
    passed: bool
    matches: List[Dict[str, Any]]
    feedback: Optional[str] = None

@dataclass
class FileResult:
    file_path: str
    language: str
    results: List[RuleResult]
    total_weight: int
    failed_weight: int
    
    @property
    def overall_status(self) -> str:
        if any(r.severity == Severity.ERROR and not r.passed for r in self.results):
            return "FAIL"
        elif any(r.severity == Severity.WARN and not r.passed for r in self.results):
            return "WARN"
        return "PASS"

class LanguageManager:
    LANGUAGE_MAP = {
        'c': 'tree_sitter_c',
        'python': 'tree_sitter_python',
        'cpp': 'tree_sitter_cpp',
        'javascript': 'tree_sitter_javascript',
        'java': 'tree_sitter_java',
    }
    
    _loaded_languages: Dict[str, Language] = {}
    
    @classmethod
    def get_language(cls, lang: str) -> Language:
        if lang in cls._loaded_languages:
            return cls._loaded_languages[lang]
            
        if lang not in cls.LANGUAGE_MAP:
            raise ValueError(f"Unsupported language: {lang}")
            
        module_name = cls.LANGUAGE_MAP[lang]
        try:
            module = __import__(module_name)
            language = Language(module.language())
            cls._loaded_languages[lang] = language
            return language
        except ImportError:
            raise ImportError(f"Language module '{module_name}' not installed. Install with: pip install {module_name}")

class CodeAnalyser:
    def __init__(self, ruleset_path: Path):
        self.ruleset_path = ruleset_path
        self.meta = self._load_ruleset()
        self.language = self.meta['language']
        self.parser = Parser(LanguageManager.get_language(self.language))
        
    def _load_ruleset(self) -> Dict[str, Any]:
        rules_file = self.ruleset_path / "rules.yaml"
        meta_file = self.ruleset_path / "meta.yaml"
        
        yaml_file = rules_file if rules_file.exists() else meta_file
        if not yaml_file.exists():
            raise FileNotFoundError(f"No rules.yaml or meta.yaml found in {self.ruleset_path}")
            
        try:
            with open(yaml_file, "r") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            logging.error("Malformed YAML in %s: %s", yaml_file, e)
            sys.exit(1)
            
        if 'language' not in data:
            raise ValueError(f"Missing required 'language' field in {yaml_file}")
        if 'rules' not in data or not data['rules']:
            raise ValueError(f"Missing or empty 'rules' section in {yaml_file}")
            
        return data
    
    def _run_query(self, source_code: bytes, query_path: Path, params: Optional[Dict] = None) -> List[Tuple[Node, str]]:
        """Execute tree-sitter query on source code"""
        if not query_path.exists():
            print(f"WARNING: Query file not found: {query_path}", file=sys.stderr)
            return []
            
        try:
            tree = self.parser.parse(source_code)
            with open(query_path, "r") as f:
                query_str = f.read()
                
            # Simple parameter substitution (could be enhanced)
            if params:
                for key, value in params.items():
                    query_str = query_str.replace(f"{{{key}}}", str(value))
                    
            query = Query(LanguageManager.get_language(self.language), query_str)
            
            # For tree-sitter 0.25+, use QueryCursor
            query_cursor = QueryCursor(query)
            captures = query_cursor.captures(tree.root_node)
            
            result = []
            # captures is a dict mapping capture names to lists of nodes
            for capture_name, node_list in captures.items():
                for node in node_list:
                    result.append((node, capture_name))
            return result
            
        except Exception as e:
            print(f"WARNING: Failed to execute query {query_path}: {e}", file=sys.stderr)
            return []
    
    def _get_file_extensions(self) -> List[str]:
        extension_map = {
            'c': ['.c', '.h'],
            'python': ['.py'],
            'cpp': ['.cpp', '.cc', '.cxx', '.hpp', '.h'],
            'javascript': ['.js', '.mjs'],
            'java': ['.java'],
        }
        return extension_map.get(self.language, [])
    
    def find_source_files(self, paths: List[Path]) -> List[Path]:
        """Find all source files of the target language in given paths"""
        extensions = self._get_file_extensions()
        if not extensions:
            print(f"WARNING: No known extensions for language '{self.language}'", file=sys.stderr)
            return []
            
        source_files = []
        for path in paths:
            if path.is_file() and path.suffix in extensions:
                source_files.append(path)
            elif path.is_dir():
                for ext in extensions:
                    source_files.extend(path.rglob(f"*{ext}"))
                    
        return sorted(source_files)
    
    def analyse_file(self, source_file: Path) -> FileResult:
        """Analyse a single source file against all rules"""
        try:
            source_code = source_file.read_bytes()
        except Exception as e:
            print(f"ERROR: Cannot read file {source_file}: {e}", file=sys.stderr)
            return FileResult(str(source_file), self.language, [], 0, 0)
            
        results = []
        total_weight = 0
        failed_weight = 0
        
        for rule_name, rule_config in self.meta['rules'].items():
            # Extract rule configuration
            query_file = self.ruleset_path / rule_config['file']
            description = rule_config.get('description', 'No description')
            severity = Severity(rule_config.get('severity', 'warn'))
            weight = rule_config.get('weight', 1)
            fail_if_matches = rule_config.get('fail_if_matches', True)
            params = rule_config.get('params', {})
            feedback = rule_config.get('feedback')
            
            total_weight += weight
            
            # Run the query
            matches = self._run_query(source_code, query_file, params)
            
            # Determine if rule passed
            has_matches = len(matches) > 0
            passed = not has_matches if fail_if_matches else has_matches
            
            if not passed:
                failed_weight += weight
            
            # Format matches for output
            match_data = []
            for node, capture_name in matches:
                try:
                    text = source_code[node.start_byte:node.end_byte].decode('utf-8', errors='replace')
                    match_data.append({
                        'capture': capture_name,
                        'text': text.strip(),
                        'line': node.start_point[0] + 1,
                        'column': node.start_point[1] + 1,
                        'byte_range': [node.start_byte, node.end_byte]
                    })
                except Exception as e:
                    print(f"WARNING: Error processing match in {source_file}: {e}", file=sys.stderr)
                    
            results.append(RuleResult(
                rule_name=rule_name,
                description=description,
                severity=severity,
                weight=weight,
                passed=passed,
                matches=match_data,
                feedback=feedback if not passed else None
            ))
            
        return FileResult(
            file_path=str(source_file),
            language=self.language,
            results=results,
            total_weight=total_weight,
            failed_weight=failed_weight
        )

def format_results(file_results: List[FileResult], output_format: str = 'json') -> str:
    if output_format == 'json':
        output = {
            'summary': {
                'total_files': len(file_results),
                'passed_files': sum(1 for f in file_results if f.overall_status == 'PASS'),
                'warned_files': sum(1 for f in file_results if f.overall_status == 'WARN'),
                'failed_files': sum(1 for f in file_results if f.overall_status == 'FAIL'),
            },
            'files': []
        }
        
        for file_result in file_results:
            file_data = {
                'file': file_result.file_path,
                'language': file_result.language,
                'status': file_result.overall_status,
                'total_weight': file_result.total_weight,
                'failed_weight': file_result.failed_weight,
                'rules': []
            }
            
            for rule in file_result.results:
                rule_data = {
                    'name': rule.rule_name,
                    'description': rule.description,
                    'severity': rule.severity.value,
                    'weight': rule.weight,
                    'passed': rule.passed,
                    'matches': rule.matches
                }
                if rule.feedback:
                    rule_data['feedback'] = rule.feedback
                file_data['rules'].append(rule_data)
                
            output['files'].append(file_data)
            
        return json.dumps(output, indent=2)
    
    elif output_format == 'summary':
        lines = []
        total_files = len(file_results)
        passed = sum(1 for f in file_results if f.overall_status == 'PASS')
        warned = sum(1 for f in file_results if f.overall_status == 'WARN')
        failed = sum(1 for f in file_results if f.overall_status == 'FAIL')
        
        lines.append(f"Analysis Summary: {total_files} files processed")
        lines.append(f"✓ Passed: {passed}, ⚠ Warned: {warned}, ✗ Failed: {failed}")
        lines.append("")
        
        for file_result in file_results:
            if file_result.overall_status != 'PASS':
                lines.append(f"{file_result.overall_status}: {file_result.file_path}")
                for rule in file_result.results:
                    if not rule.passed:
                        lines.append(f"  [{rule.severity.value.upper()}] {rule.rule_name}: {rule.description}")
                        if rule.feedback:
                            lines.append(f"    → {rule.feedback}")
                        for match in rule.matches[:3]:
                            lines.append(f"    Line {match['line']}: {match['text'][:60]}...")
                lines.append("")
                
        return "\n".join(lines)
    
    else:
        raise ValueError(f"Unknown output format: {output_format}")

def main():
    parser = argparse.ArgumentParser(
        description="Tree-sitter based code analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s src/ --ruleset rulesets/c-rules/
  %(prog)s file1.c file2.c --ruleset rulesets/c-rules/ --format summary
  %(prog)s . --ruleset rulesets/python-rules/ --format json
        """
    )
    
    parser.add_argument(
        'source_paths',
        nargs='+',
        type=Path,
        help='Source files or directories to analyse'
    )
    
    parser.add_argument(
        '--ruleset', '-r',
        type=Path,
        required=True,
        help='Path to ruleset directory containing rules.yaml or meta.yaml'
    )
    
    parser.add_argument(
        '--format', '-f',
        choices=['json', 'summary'],
        default='json',
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='WARNING',
        help='Logging level (default: WARNING)'
    )
    
    args = parser.parse_args()
    
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format='%(levelname)s: %(message)s'
    )
    
    try:
        analyser = CodeAnalyser(args.ruleset)
        
        source_files = analyser.find_source_files(args.source_paths)
        if not source_files:
            logging.error("No %s source files found in specified paths", analyser.language)
            sys.exit(1)
            
        logging.info("Analysing %d %s files...", len(source_files), analyser.language)
        
        results = []
        for source_file in source_files:
            result = analyser.analyse_file(source_file)
            results.append(result)
            
        output = format_results(results, args.format)
        print(output)
        
        has_errors = any(f.overall_status == 'FAIL' for f in results)
        sys.exit(1 if has_errors else 0)
        
    except KeyboardInterrupt:
        logging.info("Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        logging.error("%s", e)
        sys.exit(1)

if __name__ == "__main__":
    main()