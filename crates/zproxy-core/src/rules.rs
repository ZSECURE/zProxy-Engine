/// Proxification rules engine.

use crate::config::Rule;
use anyhow::Result;
use regex::Regex;

// ---------------------------------------------------------------------------
// Wildcard matching
// ---------------------------------------------------------------------------

/// Match `text` against `pattern` using `*` (any substring) and `?` (any char).
pub fn matches_wildcard(pattern: &str, text: &str) -> bool {
    wildcard_match(pattern.as_bytes(), text.as_bytes())
}

fn wildcard_match(pattern: &[u8], text: &[u8]) -> bool {
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (usize::MAX, 0usize);

    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == b'?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }
    pi == pattern.len()
}

// ---------------------------------------------------------------------------
// RuleMatcher
// ---------------------------------------------------------------------------

/// Compiled form of a [`Rule`] for efficient repeated matching.
pub struct RuleMatcher {
    rule: Rule,
    host_regex: Option<Regex>,
    process_regex: Option<Regex>,
}

impl RuleMatcher {
    pub fn new(rule: &Rule) -> Result<Self> {
        let host_regex = rule.host_pattern.as_deref().map(wildcard_to_regex).transpose()?;
        let process_regex = rule.process_pattern.as_deref().map(wildcard_to_regex).transpose()?;
        Ok(RuleMatcher {
            rule: rule.clone(),
            host_regex,
            process_regex,
        })
    }

    /// Returns `true` if this rule matches all provided criteria.
    pub fn matches(&self, host: &str, process: Option<&str>, port: Option<u16>) -> bool {
        // Host pattern
        if let Some(ref re) = self.host_regex {
            if !re.is_match(host) {
                return false;
            }
        }
        // Process pattern
        if let Some(ref re) = self.process_regex {
            match process {
                Some(p) if re.is_match(p) => {}
                _ => return false,
            }
        }
        // Port
        if let Some(rule_port) = self.rule.port {
            if port != Some(rule_port) {
                return false;
            }
        }
        true
    }

    pub fn rule(&self) -> &Rule {
        &self.rule
    }
}

/// Convert a wildcard pattern to a full-match regex.
fn wildcard_to_regex(pattern: &str) -> Result<Regex> {
    let mut re = String::from("(?i)^");
    for ch in pattern.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            c => {
                re.push_str(&regex::escape(&c.to_string()));
            }
        }
    }
    re.push('$');
    Ok(Regex::new(&re)?)
}

// ---------------------------------------------------------------------------
// CompiledRules – pre-sorted and pre-compiled for efficient hot-path lookups
// ---------------------------------------------------------------------------

/// Pre-sorted, pre-compiled set of rules for efficient per-connection lookup.
///
/// Build once at startup via [`CompiledRules::new`], then reuse for every
/// connection to avoid per-connection regex compilation and Vec allocations.
pub struct CompiledRules {
    matchers: Vec<RuleMatcher>, // sorted by descending priority
}

impl CompiledRules {
    /// Compile and sort a slice of rules.
    pub fn new(rules: &[Rule]) -> Result<Self> {
        let mut matchers: Vec<RuleMatcher> = rules
            .iter()
            .map(RuleMatcher::new)
            .collect::<Result<Vec<_>>>()?;
        matchers.sort_by(|a, b| b.rule().priority.cmp(&a.rule().priority));
        Ok(CompiledRules { matchers })
    }

    /// Find the first matching rule for the given connection attributes.
    pub fn find_match(
        &self,
        host: &str,
        process: Option<&str>,
        port: Option<u16>,
    ) -> Option<&Rule> {
        self.matchers.iter().find_map(|m| {
            if m.matches(host, process, port) {
                Some(m.rule())
            } else {
                None
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Rule lookup
// ---------------------------------------------------------------------------

/// Find the highest-priority matching rule for the given connection attributes.
///
/// Rules are sorted by descending priority; the first match wins.
pub fn find_matching_rule<'a>(
    rules: &'a [Rule],
    host: &str,
    process: Option<&str>,
    port: Option<u16>,
) -> Option<&'a Rule> {
    let mut sorted: Vec<&Rule> = rules.iter().collect();
    sorted.sort_by(|a, b| b.priority.cmp(&a.priority));

    for rule in sorted {
        if let Ok(matcher) = RuleMatcher::new(rule) {
            if matcher.matches(host, process, port) {
                return Some(rule);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wildcard_star() {
        assert!(matches_wildcard("*.example.com", "sub.example.com"));
        assert!(matches_wildcard("*.example.com", "a.b.example.com"));
        assert!(!matches_wildcard("*.example.com", "example.com"));
        assert!(matches_wildcard("*", "anything"));
        assert!(matches_wildcard("*", ""));
    }

    #[test]
    fn test_wildcard_question() {
        assert!(matches_wildcard("h?llo", "hello"));
        assert!(matches_wildcard("h?llo", "hallo"));
        assert!(!matches_wildcard("h?llo", "hllo"));
    }

    #[test]
    fn test_wildcard_exact() {
        assert!(matches_wildcard("example.com", "example.com"));
        assert!(!matches_wildcard("example.com", "notexample.com"));
    }

    #[test]
    fn test_wildcard_prefix_suffix() {
        assert!(matches_wildcard("ad*", "ads.google.com"));
        assert!(matches_wildcard("*tracker*", "pixel.tracker.io"));
        assert!(!matches_wildcard("*tracker*", "example.com"));
    }

    #[test]
    fn test_rule_matcher_host_only() {
        use crate::config::{Rule, RuleAction};
        let rule = Rule {
            id: "r1".into(),
            name: "test".into(),
            host_pattern: Some("*.ads.com".into()),
            process_pattern: None,
            port: None,
            action: RuleAction::Block,
            priority: 10,
        };
        let matcher = RuleMatcher::new(&rule).unwrap();
        assert!(matcher.matches("banner.ads.com", None, None));
        assert!(!matcher.matches("example.com", None, None));
    }

    #[test]
    fn test_rule_matcher_port() {
        use crate::config::{Rule, RuleAction};
        let rule = Rule {
            id: "r2".into(),
            name: "http only".into(),
            host_pattern: None,
            process_pattern: None,
            port: Some(80),
            action: RuleAction::Direct,
            priority: 5,
        };
        let matcher = RuleMatcher::new(&rule).unwrap();
        assert!(matcher.matches("any.host", None, Some(80)));
        assert!(!matcher.matches("any.host", None, Some(443)));
    }

    #[test]
    fn test_find_matching_rule_priority() {
        use crate::config::{Rule, RuleAction};
        let rules = vec![
            Rule {
                id: "low".into(),
                name: "low prio".into(),
                host_pattern: Some("*".into()),
                process_pattern: None,
                port: None,
                action: RuleAction::Direct,
                priority: 1,
            },
            Rule {
                id: "high".into(),
                name: "high prio".into(),
                host_pattern: Some("*.blocked.com".into()),
                process_pattern: None,
                port: None,
                action: RuleAction::Block,
                priority: 100,
            },
        ];
        let result = find_matching_rule(&rules, "evil.blocked.com", None, None);
        assert_eq!(result.unwrap().id, "high");
    }

    #[test]
    fn test_compiled_rules_precompiled() {
        use crate::config::{Rule, RuleAction};
        let rules = vec![
            Rule {
                id: "low".into(),
                name: "catch-all".into(),
                host_pattern: Some("*".into()),
                process_pattern: None,
                port: None,
                action: RuleAction::Direct,
                priority: 1,
            },
            Rule {
                id: "high".into(),
                name: "block bad".into(),
                host_pattern: Some("*.bad.com".into()),
                process_pattern: None,
                port: None,
                action: RuleAction::Block,
                priority: 50,
            },
        ];
        let compiled = CompiledRules::new(&rules).unwrap();
        // High priority rule should win
        assert_eq!(compiled.find_match("evil.bad.com", None, None).unwrap().id, "high");
        // Low priority catch-all should win when no specific rule matches
        assert_eq!(compiled.find_match("safe.example.com", None, None).unwrap().id, "low");
        // No match when neither pattern fits
        let empty = CompiledRules::new(&[]).unwrap();
        assert!(empty.find_match("anything.com", None, None).is_none());
    }
}
