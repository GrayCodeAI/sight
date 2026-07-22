package sight

// defaultRules returns the built-in set of static analysis rules across all
// supported languages. Rules are organized by language in separate files:
//
//   - static_rules_go.go          — Go security & correctness
//   - static_rules_python.go      — Python security
//   - static_rules_typescript.go  — TypeScript/JavaScript security
//   - static_rules_performance.go — Performance (all languages)
//   - static_rules_systems.go     — Any-language, Rust, C, C++ security
//   - static_rules_java.go        — Java security
//   - static_rules_ruby.go        — Ruby security
//   - static_rules_sql.go         — SQL security
func defaultRules() []StaticRule {
	var rules []StaticRule
	rules = append(rules, goSecurityRules()...)
	rules = append(rules, goCorrectnessRules()...)
	rules = append(rules, pythonSecurityRules()...)
	rules = append(rules, typescriptSecurityRules()...)
	rules = append(rules, performanceRules()...)
	rules = append(rules, systemsSecurityRules()...)
	rules = append(rules, javaSecurityRules()...)
	rules = append(rules, rubySecurityRules()...)
	rules = append(rules, sqlSecurityRules()...)
	return rules
}
