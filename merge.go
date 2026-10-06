// SPDX-License-Identifier: BSD-2-Clause

package main

// Merge Docker's and Podman's default seccomp profiles into one profile that works with
// both, picking the most hardened rule from each.
//
// The two profiles are compared one syscall name at a time:
//
//   - If only one profile has rules for the syscall, they are kept as they are. The other
//     engine's default would deny it, but that is not a decision about this syscall: it is
//     often just a newer syscall (mseal, uretprobe, ...) or an old one it never listed.
//   - If both do, an ALLOW survives only where both allow: each Docker ALLOW rule is ANDed
//     with each Podman ALLOW rule (capabilities and arches required by either, kernel
//     version the newer of the two, argument checks from both), and contradictory or
//     redundant combinations are dropped. This is what makes e.g. socket() come out right --
//     Docker restricts the address family, Podman the netlink protocol, and both have to
//     hold -- with no per-syscall special cases. Pairs of rules that differ only in a
//     capability being required by one and excluded by the other are one rule without it.
//   - Explicit denies (ERRNO and the like) from either profile are kept, with their errno,
//     so a deny from either engine wins. A syscall that one engine allows and the other
//     denies outright (futex_wait, vmsplice, ...) ends up denied.
//
// libseccomp does not define what happens when an ALLOW and a deny for the same syscall
// overlap (compiled, Podman's own setns comes out allowed although its profile denies it
// without CAP_SYS_ADMIN), so the merge refuses to produce such a profile: for each syscall
// the rules with different actions must be provably disjoint.
//
// Other choices:
//   - defaultErrnoRet/defaultErrno follow Podman's ENOSYS (the modern recommended choice over
//     Docker's EPERM), and archMap is the union of both engines' declared architectures (an
//     arch entry only affects whether the profile can load on that architecture, not what's
//     allowed on the one a container is actually running on).
//   - socketcall (legacy multiplexed socket syscall, mostly 32-bit x86) is left as both
//     upstreams have it: seccomp can't see its real arguments, so the socket() restrictions
//     don't apply to it. Docker tried blocking it outright (moby/profiles 7158007a8300) and
//     reverted (3c2832431472) because it broke too much x86 userland. Closing that gap needs
//     AppArmor or SELinux.
//   - Comments are kept on rules copied unchanged and dropped from merged ones.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"
)

const (
	actAllow = "SCMP_ACT_ALLOW"
	actErrno = "SCMP_ACT_ERRNO"

	opEQ       = "SCMP_CMP_EQ"
	opNE       = "SCMP_CMP_NE"
	opLT       = "SCMP_CMP_LT"
	opLE       = "SCMP_CMP_LE"
	opGT       = "SCMP_CMP_GT"
	opGE       = "SCMP_CMP_GE"
	opMaskedEQ = "SCMP_CMP_MASKED_EQ"
)

// strictDecode rejects unknown fields, so a condition this merge doesn't know how to
// combine aborts it instead of being silently dropped.
func strictDecode(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Arg is one argument comparison of a rule.
type Arg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	ValueTwo uint64 `json:"valueTwo,omitempty"` // Podman writes 0 explicitly; it is the default
	Op       string `json:"op"`
}

func (a *Arg) UnmarshalJSON(b []byte) error {
	type plain Arg
	return strictDecode(b, (*plain)(a))
}

// Cond is the includes/excludes gating of a rule. excludes has no minKernel.
type Cond struct {
	Caps      []string `json:"caps,omitempty"`
	Arches    []string `json:"arches,omitempty"`
	MinKernel string   `json:"minKernel,omitempty"`
}

func (c *Cond) UnmarshalJSON(b []byte) error {
	type plain Cond
	return strictDecode(b, (*plain)(c))
}

func (c *Cond) empty() bool {
	return c == nil || (len(c.Caps) == 0 && len(c.Arches) == 0 && c.MinKernel == "")
}

// nonEmpty is nil if nothing is left in c.
func (c *Cond) nonEmpty() *Cond {
	if c.empty() {
		return nil
	}
	return c
}

// ArchEntry is an archMap entry. SubArchitectures stays raw to keep an upstream null.
type ArchEntry struct {
	Architecture     string          `json:"architecture"`
	SubArchitectures json.RawMessage `json:"subArchitectures,omitempty"`
}

// Rule is one entry from a profile's syscalls list for one syscall name.
type Rule struct {
	Name     string
	Action   string
	Comment  string
	Args     []Arg
	Includes *Cond
	Excludes *Cond
	ErrnoRet *int
	Errno    *string
}

// Profile is a parsed OCI Linux seccomp profile.
type Profile struct {
	DefaultAction   string
	DefaultErrnoRet *int
	DefaultErrno    *string
	ArchMap         []ArchEntry
	Syscalls        []Rule
}

type rawRule struct {
	Names    []string `json:"names"`
	Action   string   `json:"action"`
	Comment  string   `json:"comment"`
	Args     []Arg    `json:"args"`
	Includes *Cond    `json:"includes"`
	Excludes *Cond    `json:"excludes"`
	ErrnoRet *int     `json:"errnoRet"`
	Errno    *string  `json:"errno"`
}

type rawProfile struct {
	DefaultAction   string      `json:"defaultAction"`
	DefaultErrnoRet *int        `json:"defaultErrnoRet"`
	DefaultErrno    *string     `json:"defaultErrno"`
	ArchMap         []ArchEntry `json:"archMap"`
	Syscalls        []rawRule   `json:"syscalls"`
}

// parseProfile parses an OCI seccomp profile. Rules naming several syscalls are split
// into one Rule per name.
func parseProfile(data []byte) (*Profile, error) {
	var raw rawProfile
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw.DefaultAction == "" {
		return nil, fmt.Errorf("no defaultAction")
	}
	p := &Profile{
		DefaultAction:   raw.DefaultAction,
		DefaultErrnoRet: raw.DefaultErrnoRet,
		DefaultErrno:    raw.DefaultErrno,
		ArchMap:         raw.ArchMap,
	}
	for _, r := range raw.Syscalls {
		if r.Excludes != nil && r.Excludes.MinKernel != "" {
			return nil, fmt.Errorf("unsupported excludes.minKernel in %v", r.Names)
		}
		for _, c := range []*Cond{r.Includes, r.Excludes} {
			if c != nil && c.MinKernel != "" {
				if _, err := kernelKey(c.MinKernel); err != nil {
					return nil, err
				}
			}
		}
		for _, name := range r.Names {
			p.Syscalls = append(p.Syscalls, Rule{
				Name:     name,
				Action:   r.Action,
				Comment:  r.Comment,
				Args:     r.Args,
				Includes: r.Includes.nonEmpty(),
				Excludes: r.Excludes.nonEmpty(),
				ErrnoRet: r.ErrnoRet,
				Errno:    r.Errno,
			})
		}
	}
	return p, nil
}

// rulesByName maps syscall name to its rules, in profile order.
func rulesByName(p *Profile) map[string][]Rule {
	out := map[string][]Rule{}
	for _, r := range p.Syscalls {
		out[r.Name] = append(out[r.Name], r)
	}
	return out
}

func filterRules(rules []Rule, allow bool) []Rule {
	var out []Rule
	for _, r := range rules {
		if (r.Action == actAllow) == allow {
			out = append(out, r)
		}
	}
	return out
}

func decodeStrings(raw json.RawMessage) []string {
	var s []string
	_ = json.Unmarshal(raw, &s) // null and absent give nil
	return s
}

// unionArchMaps combines the architecture entries declared by either profile.
func unionArchMaps(a, b []ArchEntry) []ArchEntry {
	out := []ArchEntry{}
	index := map[string]int{}
	for _, e := range slices.Concat(a, b) {
		i, ok := index[e.Architecture]
		if !ok {
			index[e.Architecture] = len(out)
			out = append(out, e)
			continue
		}
		subs := union(decodeStrings(out[i].SubArchitectures), decodeStrings(e.SubArchitectures))
		if len(subs) > 0 {
			out[i].SubArchitectures, _ = json.Marshal(subs)
		}
	}
	return out
}

// reduceComparisons ANDs together plain comparisons (EQ/NE/LT/LE/GT/GE) on one argument.
// It returns the minimal equivalent list, or false if no value can satisfy them all.
func reduceComparisons(index uint, comparisons []Arg) ([]Arg, bool) {
	lo, hi := uint64(0), uint64(math.MaxUint64)
	excluded := map[uint64]bool{}
	for _, c := range comparisons {
		v := c.Value
		switch c.Op {
		case opEQ:
			lo, hi = max(lo, v), min(hi, v)
		case opLT:
			if v == 0 {
				return nil, false
			}
			hi = min(hi, v-1)
		case opLE:
			hi = min(hi, v)
		case opGT:
			if v == math.MaxUint64 {
				return nil, false
			}
			lo = max(lo, v+1)
		case opGE:
			lo = max(lo, v)
		case opNE:
			excluded[v] = true
		}
	}
	if lo > hi || (lo == hi && excluded[lo]) {
		return nil, false
	}
	if lo == hi {
		return []Arg{{Index: index, Value: lo, Op: opEQ}}, true
	}
	var bounds, ne []Arg
	for _, c := range comparisons {
		if c.Op != opNE {
			bounds = append(bounds, c)
		} else if lo <= c.Value && c.Value <= hi {
			ne = append(ne, c)
		}
	}
	return append(bounds, ne...), true
}

// combineArgs ANDs together argument comparisons from two rules; false if they contradict.
func combineArgs(args []Arg) ([]Arg, bool) {
	var unique []Arg
	for _, a := range args {
		if !slices.Contains(unique, a) {
			unique = append(unique, a)
		}
	}
	var order []uint
	byIndex := map[uint][]Arg{}
	for _, a := range unique {
		if _, ok := byIndex[a.Index]; !ok {
			order = append(order, a.Index)
		}
		byIndex[a.Index] = append(byIndex[a.Index], a)
	}
	var combined []Arg
	for _, index := range order {
		var plain, masked []Arg
		for _, a := range byIndex[index] {
			if a.Op == opMaskedEQ {
				masked = append(masked, a)
			} else {
				plain = append(plain, a)
			}
		}
		if len(plain) > 0 {
			reduced, ok := reduceComparisons(index, plain)
			if !ok {
				return nil, false
			}
			combined = append(combined, reduced...)
		}
		combined = append(combined, masked...)
	}
	return combined, true
}

// kernelKey parses a dotted kernel version like "4.8"; "" is "0".
func kernelKey(version string) ([]int, error) {
	if version == "" {
		return []int{0}, nil
	}
	var key []int
	for part := range strings.SplitSeq(version, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("bad minKernel %q", version)
		}
		key = append(key, n)
	}
	return key, nil
}

// compareKernel orders versions already checked by parseProfile.
func compareKernel(a, b string) int {
	ka, _ := kernelKey(a)
	kb, _ := kernelKey(b)
	return slices.Compare(ka, kb)
}

func cond(c *Cond) Cond {
	if c == nil {
		return Cond{}
	}
	return *c
}

// intersectRules returns a rule allowing name only when both a and b would; false if that's
// never.
//
// Runtime semantics: includes.caps needs ALL listed caps, excludes.caps drops the rule if
// ANY is present; includes.arches / excludes.arches are matched against the container arch;
// includes.minKernel needs kernel >= version; a rule's args must all match.
func intersectRules(name string, a, b Rule) (Rule, bool) {
	incA, incB := cond(a.Includes), cond(b.Includes)
	excA, excB := cond(a.Excludes), cond(b.Excludes)

	incCaps := union(incA.Caps, incB.Caps)
	excCaps := union(excA.Caps, excB.Caps)
	if len(intersection(incCaps, excCaps)) > 0 {
		return Rule{}, false
	}

	excArches := union(excA.Arches, excB.Arches)
	var incArches []string
	var sets [][]string
	for _, inc := range []Cond{incA, incB} {
		if inc.Arches != nil {
			sets = append(sets, inc.Arches)
		}
	}
	if len(sets) > 0 {
		incArches = difference(intersection(sets...), excArches)
		if len(incArches) == 0 {
			return Rule{}, false
		}
		excArches = nil
	}

	args, ok := combineArgs(slices.Concat(a.Args, b.Args))
	if !ok {
		return Rule{}, false
	}

	minKernel := ""
	for _, inc := range []Cond{incA, incB} {
		if inc.MinKernel != "" && (minKernel == "" || compareKernel(inc.MinKernel, minKernel) > 0) {
			minKernel = inc.MinKernel
		}
	}
	return Rule{
		Name:     name,
		Action:   actAllow,
		Args:     args,
		Includes: (&Cond{Caps: incCaps, Arches: incArches, MinKernel: minKernel}).nonEmpty(),
		Excludes: (&Cond{Caps: excCaps, Arches: excArches}).nonEmpty(),
	}, true
}

// noStricter reports whether every call rule b allows is also allowed by rule a.
func noStricter(a, b Rule) bool {
	incA, incB := cond(a.Includes), cond(b.Includes)
	excA, excB := cond(a.Excludes), cond(b.Excludes)
	return subset(incA.Caps, incB.Caps) &&
		subset(excA.Caps, excB.Caps) &&
		subset(excA.Arches, excB.Arches) &&
		compareKernel(incA.MinKernel, incB.MinKernel) <= 0 &&
		(incA.Arches == nil || subset(incB.Arches, incA.Arches)) &&
		subsetFunc(a.Args, b.Args)
}

// dropRedundant removes rules (alternatives) already covered by a less strict rule in the list.
func dropRedundant(rules []Rule) []Rule {
	var kept []Rule
	for i, rule := range rules {
		covered := false
		for j, other := range rules {
			if j != i && noStricter(other, rule) && (j < i || !noStricter(rule, other)) {
				covered = true
				break
			}
		}
		if !covered {
			kept = append(kept, rule)
		}
	}
	return kept
}

// merge applies the merge policy described at the top of this file.
func merge(docker, podman *Profile) *Profile {
	dockerRules := rulesByName(docker)
	podmanRules := rulesByName(podman)

	var names []string
	for name := range dockerRules {
		names = append(names, name)
	}
	for name := range podmanRules {
		if _, ok := dockerRules[name]; !ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	var merged []Rule
	for _, name := range names {
		d, p := dockerRules[name], podmanRules[name]
		switch {
		case len(p) == 0:
			merged = append(merged, d...)
		case len(d) == 0:
			merged = append(merged, p...)
		default:
			merged = append(merged, combine(name, d, p)...)
		}
	}
	// libseccomp refuses a rule whose action is the default one, and it would add nothing:
	// no ALLOW overlaps a deny (see validate), so the call falls through to the same action.
	merged = slices.DeleteFunc(merged, func(r Rule) bool {
		return r.Action == actErrno && errnoOf(r.ErrnoRet) == errnoOf(podman.DefaultErrnoRet)
	})
	return &Profile{
		DefaultAction:   actErrno,
		DefaultErrnoRet: podman.DefaultErrnoRet,
		DefaultErrno:    podman.DefaultErrno,
		ArchMap:         unionArchMaps(docker.ArchMap, podman.ArchMap),
		Syscalls:        merged,
	}
}

// errnoOf is the errno of an ERRNO action: EPERM if the profile doesn't say.
func errnoOf(p *int) int {
	if p == nil {
		return 1
	}
	return *p
}

// combine merges the rules both profiles have for one syscall.
func combine(name string, d, p []Rule) []Rule {
	var denies []Rule
	seen := map[string]bool{}
	for _, r := range slices.Concat(filterRules(d, false), filterRules(p, false)) {
		if key := ruleKey(r); !seen[key] {
			seen[key] = true
			denies = append(denies, r)
		}
	}
	denies = dropRedundantDenies(denies)

	var alternatives []Rule
	for _, da := range filterRules(d, true) {
		for _, pa := range filterRules(p, true) {
			if r, ok := intersectRules(name, da, pa); ok {
				alternatives = append(alternatives, r)
			}
		}
	}
	for _, deny := range denies {
		alternatives = subtract(name, alternatives, deny)
	}
	return append(dropRedundant(collapseComplements(dropRedundant(alternatives))), denies...)
}

// dropRedundantDenies removes denies whose calls another deny with the same action covers.
func dropRedundantDenies(denies []Rule) []Rule {
	var out []Rule
	for _, group := range groupBy(denies, func(r Rule) string {
		key, _ := json.Marshal([]any{r.Action, r.ErrnoRet, r.Errno})
		return string(key)
	}) {
		out = append(out, dropRedundant(group)...)
	}
	return out
}

// groupBy splits rules by key, in order of first appearance.
func groupBy(rules []Rule, key func(Rule) string) [][]Rule {
	var groups [][]Rule
	index := map[string]int{}
	for _, r := range rules {
		k := key(r)
		i, ok := index[k]
		if !ok {
			i = len(groups)
			index[k] = i
			groups = append(groups, nil)
		}
		groups[i] = append(groups[i], r)
	}
	return groups
}

// subtract removes from the ALLOW rules the calls that deny catches, so the two can't
// overlap. That is only possible when deny is just "none of these capabilities" (as in
// Podman's perf_event_open: ERRNO unless CAP_SYS_ADMIN): the allow must then require one
// of them. For any other deny the rules are left alone, and validate rejects an overlap.
func subtract(name string, allows []Rule, deny Rule) []Rule {
	simple := len(deny.Args) == 0 && deny.Includes == nil && deny.Excludes != nil &&
		len(deny.Excludes.Arches) == 0
	var out []Rule
	for _, a := range allows {
		if _, overlap := intersectRules(name, a, deny); !overlap || !simple {
			out = append(out, a)
			continue
		}
		for _, c := range deny.Excludes.Caps {
			if r, ok := intersectRules(name, a, Rule{Includes: &Cond{Caps: []string{c}}}); ok {
				out = append(out, r)
			}
		}
	}
	return out
}

// collapseComplements joins rules that differ only in a capability being required by one and
// excluded by the other: together they allow the call with or without it.
func collapseComplements(rules []Rule) []Rule {
	for changed := true; changed; {
		changed = false
	search:
		for i := range rules {
			for j := range rules {
				if i == j {
					continue
				}
				if r, ok := complement(rules[i], rules[j]); ok {
					rules[i] = r
					rules = slices.Delete(rules, j, j+1)
					changed = true
					break search
				}
			}
		}
	}
	return rules
}

// complement returns a without cap C, if a excludes C and b requires it and the two are
// otherwise the same.
func complement(a, b Rule) (Rule, bool) {
	incA, incB := cond(a.Includes), cond(b.Includes)
	excA, excB := cond(a.Excludes), cond(b.Excludes)
	for _, c := range incB.Caps {
		if !slices.Contains(excA.Caps, c) {
			continue
		}
		excCaps := difference(excA.Caps, []string{c})
		if subset(incA.Caps, difference(incB.Caps, []string{c})) &&
			subset(difference(incB.Caps, []string{c}), incA.Caps) &&
			subset(excCaps, excB.Caps) && subset(excB.Caps, excCaps) &&
			(incA.Arches == nil) == (incB.Arches == nil) &&
			subset(incA.Arches, incB.Arches) && subset(incB.Arches, incA.Arches) &&
			subset(excA.Arches, excB.Arches) && subset(excB.Arches, excA.Arches) &&
			incA.MinKernel == incB.MinKernel &&
			subsetFunc(a.Args, b.Args) && subsetFunc(b.Args, a.Args) {
			a.Excludes = (&Cond{Caps: excCaps, Arches: excA.Arches}).nonEmpty()
			return a, true
		}
	}
	return Rule{}, false
}

// ruleKey identifies a rule ignoring its name.
func ruleKey(r Rule) string {
	key, _ := json.Marshal(outRule{Action: r.Action, Comment: r.Comment, Includes: r.Includes,
		Excludes: r.Excludes, Args: r.Args, ErrnoRet: r.ErrnoRet, Errno: r.Errno})
	return string(key)
}

type outRule struct {
	Names    []string `json:"names"`
	Action   string   `json:"action"`
	Comment  string   `json:"comment,omitempty"`
	Includes *Cond    `json:"includes,omitempty"`
	Excludes *Cond    `json:"excludes,omitempty"`
	Args     []Arg    `json:"args,omitempty"`
	ErrnoRet *int     `json:"errnoRet,omitempty"`
	Errno    *string  `json:"errno,omitempty"`
}

type outProfile struct {
	DefaultAction   string      `json:"defaultAction"`
	DefaultErrnoRet *int        `json:"defaultErrnoRet,omitempty"`
	DefaultErrno    *string     `json:"defaultErrno,omitempty"`
	ArchMap         []ArchEntry `json:"archMap"`
	Syscalls        []outRule   `json:"syscalls"`
}

// toJSON builds the canonical, upstream-style profile, regrouping rules that share
// everything but the name into one entry with a combined, sorted names list.
func toJSON(p *Profile) (outProfile, error) {
	var groups []*outRule
	index := map[string]*outRule{}
	for _, r := range p.Syscalls {
		key := ruleKey(r)
		if index[key] == nil {
			g := outRule{Action: r.Action, Comment: r.Comment, Includes: r.Includes, Excludes: r.Excludes,
				Args: r.Args, ErrnoRet: r.ErrnoRet, Errno: r.Errno}
			index[key] = &g
			groups = append(groups, &g)
		}
		index[key].Names = append(index[key].Names, r.Name)
	}
	out := outProfile{
		DefaultAction:   p.DefaultAction,
		DefaultErrnoRet: p.DefaultErrnoRet,
		DefaultErrno:    p.DefaultErrno,
		ArchMap:         p.ArchMap,
		Syscalls:        []outRule{},
	}
	for _, g := range groups {
		sort.Strings(g.Names)
		g.Names = slices.Compact(g.Names)
		out.Syscalls = append(out.Syscalls, *g)
	}
	return out, nil
}

// validate checks the merged profile against the two sources. It returns human-readable
// errors; empty means the merge is consistent:
//   - a syscall is allowed only if every engine that has rules for it allows it somewhere;
//   - rules of one syscall with different actions can't overlap.
func validate(merged, docker, podman *Profile) []string {
	var errs []string
	if len(merged.Syscalls) == 0 {
		errs = append(errs, "merged profile has no syscall rules")
	}
	engines := []struct {
		name  string
		rules map[string][]Rule
	}{{"Docker", rulesByName(docker)}, {"Podman", rulesByName(podman)}}

	byName := rulesByName(merged)
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		rules := byName[name]
		if len(filterRules(rules, true)) > 0 {
			for _, e := range engines {
				if r := e.rules[name]; len(r) > 0 && len(filterRules(r, true)) == 0 {
					errs = append(errs, name+": allowed in output but denied by "+e.name)
				}
			}
		}
		for i, a := range rules {
			for _, b := range rules[i+1:] {
				if a.Action == b.Action && slices.Equal(ptrs(a.ErrnoRet), ptrs(b.ErrnoRet)) {
					continue
				}
				if _, overlap := intersectRules(name, a, b); overlap {
					errs = append(errs, name+": rules with different actions may overlap")
				}
			}
		}
	}
	return errs
}

func ptrs(p *int) []int {
	if p == nil {
		return nil
	}
	return []int{*p}
}

// set helpers: inputs are treated as sets, results are sorted and deduplicated.

func union(a, b []string) []string {
	out := slices.Concat(a, b)
	sort.Strings(out)
	return slices.Compact(out)
}

func intersection(sets ...[]string) []string {
	var out []string
	for _, s := range sets[0] {
		if !slices.Contains(out, s) && !slices.ContainsFunc(sets[1:], func(o []string) bool { return !slices.Contains(o, s) }) {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func difference(a, b []string) []string {
	var out []string
	for _, s := range a {
		if !slices.Contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}

func subset(a, b []string) bool {
	for _, s := range a {
		if !slices.Contains(b, s) {
			return false
		}
	}
	return true
}

func subsetFunc(a, b []Arg) bool {
	for _, s := range a {
		if !slices.Contains(b, s) {
			return false
		}
	}
	return true
}
