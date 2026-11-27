# Scope Guard policy for OPA. Mirrors apps/api/opt_api/scope.py; both must agree.
package opt.scope

import rego.v1

default allow := false

allow if {
	not input.engagement.locked
	roe_valid
	in_scope
	verified_if_active
	window_ok_if_active
}

roe_valid if {
	time.parse_rfc3339_ns(input.engagement.roe_valid_from) <= time.now_ns()
	time.now_ns() <= time.parse_rfc3339_ns(input.engagement.roe_valid_to)
}

matches(rule) if {
	rule.kind == "domain"
	t := lower(trim_suffix(input.target, "."))
	d := lower(trim_prefix(rule.value, "*."))
	t == d
}

matches(rule) if {
	rule.kind == "domain"
	t := lower(trim_suffix(input.target, "."))
	d := lower(trim_prefix(rule.value, "*."))
	endswith(t, concat("", [".", d]))
}

matches(rule) if {
	rule.kind == "cidr"
	net.cidr_contains(rule.value, input.target)
}

in_scope if {
	some r in input.engagement.rules
	not r.exclude
	matches(r)
	not excluded
}

excluded if {
	some r in input.engagement.rules
	r.exclude
	matches(r)
}

verified_if_active if input.risk == "passive"

verified_if_active if input.target_verified == true

# Scan windows are evaluated by the API (Vietnam time) and passed in as a flag.
window_ok_if_active if input.risk == "passive"

window_ok_if_active if input.in_window == true
