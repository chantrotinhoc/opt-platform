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

# "example.vn" matches the apex and every subdomain.
matches(rule) if {
	rule.kind == "domain"
	not startswith(rule.value, "*.")
	t := lower(trim_suffix(input.target, "."))
	t == lower(trim_suffix(rule.value, "."))
}

matches(rule) if {
	rule.kind == "domain"
	not startswith(rule.value, "*.")
	t := lower(trim_suffix(input.target, "."))
	endswith(t, concat("", [".", lower(trim_suffix(rule.value, "."))]))
}

# "*.example.vn" matches subdomains only, not the apex.
matches(rule) if {
	rule.kind == "domain"
	startswith(rule.value, "*.")
	t := lower(trim_suffix(input.target, "."))
	endswith(t, lower(trim_suffix(substring(rule.value, 1, -1), ".")))
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
