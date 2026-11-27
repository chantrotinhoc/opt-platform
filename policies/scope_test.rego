package opt.scope_test

import rego.v1

import data.opt.scope

eng := {
	"locked": false,
	"roe_valid_from": "2020-01-01T00:00:00Z",
	"roe_valid_to": "2099-01-01T00:00:00Z",
	"rules": [
		{"kind": "domain", "value": "example.vn", "exclude": false},
		{"kind": "domain", "value": "pay.example.vn", "exclude": true},
		{"kind": "cidr", "value": "203.0.113.0/24", "exclude": false},
	],
}

test_in_scope_allowed if {
	scope.allow with input as {"engagement": eng, "target": "app.example.vn", "risk": "low", "target_verified": true, "in_window": true}
}

test_excluded_denied if {
	not scope.allow with input as {"engagement": eng, "target": "pay.example.vn", "risk": "passive"}
}

test_unverified_active_denied if {
	not scope.allow with input as {"engagement": eng, "target": "203.0.113.9", "risk": "medium", "target_verified": false, "in_window": true}
}

test_lookalike_denied if {
	not scope.allow with input as {"engagement": eng, "target": "evil-example.vn", "risk": "passive"}
}

test_wildcard_excludes_apex if {
	wild := object.union(eng, {"rules": [{"kind": "domain", "value": "*.example.vn", "exclude": false}]})
	scope.allow with input as {"engagement": wild, "target": "a.example.vn", "risk": "passive"}
	not scope.allow with input as {"engagement": wild, "target": "example.vn", "risk": "passive"}
}

test_high_risk_requires_verification if {
	not scope.allow with input as {"engagement": eng, "target": "app.example.vn", "risk": "high", "target_verified": false, "in_window": true}
}

test_trailing_dot_rules_match_like_python if {
	dotted := object.union(eng, {"rules": [
		{"kind": "domain", "value": "example.vn.", "exclude": false},
		{"kind": "domain", "value": "pay.example.vn.", "exclude": true},
	]})
	scope.allow with input as {"engagement": dotted, "target": "app.example.vn", "risk": "passive"}
	not scope.allow with input as {"engagement": dotted, "target": "pay.example.vn", "risk": "passive"}
}
