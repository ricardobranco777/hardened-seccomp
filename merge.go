// SPDX-License-Identifier: BSD-2-Clause

package main

// Merge Docker's and Podman's default seccomp profiles into one profile that works with
// both: the strictest rule from either runtime wins.
//
// A syscall is allowed only if BOTH profiles allow it, and only when the conditions of the
// rule that allows it in each profile hold at the same time. Each profile lists several
// ALLOW rules per syscall (alternatives), so the merge intersects them pairwise: every
// Docker rule is ANDed with every Podman rule (capabilities and arches required by either,
// kernel version the newer of the two, argument checks from both), and contradictory or
// redundant combinations are dropped. This is what makes e.g. socket() come out right --
// Docker restricts the address family, Podman the netlink protocol, and both have to hold --
// with no per-syscall special cases.
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
	Args     []Arg
	Includes *Cond
	Excludes *Cond
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
	Args     []Arg    `json:"args"`
	Includes *Cond    `json:"includes"`
	Excludes *Cond    `json:"excludes"`
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
				Args:     r.Args,
				Includes: r.Includes.nonEmpty(),
				Excludes: r.Excludes.nonEmpty(),
			})
		}
	}
	return p, nil
}

// allowRulesByName maps syscall name to its SCMP_ACT_ALLOW rules.
//
// Both profiles mix a handful of explicit per-syscall SCMP_ACT_ERRNO rules in among the
// ALLOW rules (redundant capability restatements, or explicit always-on denies). Only
// ALLOW rules define what a profile actually allows, so those are ignored here.
func allowRulesByName(p *Profile) map[string][]Rule {
	out := map[string][]Rule{}
	for _, r := range p.Syscalls {
		if r.Action == actAllow {
			out[r.Name] = append(out[r.Name], r)
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
	dockerRules := allowRulesByName(docker)
	podmanRules := allowRulesByName(podman)

	var names []string
	for name := range dockerRules {
		if _, ok := podmanRules[name]; ok {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	var merged []Rule
	for _, name := range names {
		var alternatives []Rule
		for _, d := range dockerRules[name] {
			for _, p := range podmanRules[name] {
				if r, ok := intersectRules(name, d, p); ok {
					alternatives = append(alternatives, r)
				}
			}
		}
		merged = append(merged, dropRedundant(alternatives)...)
	}
	return &Profile{
		DefaultAction:   actErrno,
		DefaultErrnoRet: podman.DefaultErrnoRet,
		DefaultErrno:    podman.DefaultErrno,
		ArchMap:         unionArchMaps(docker.ArchMap, podman.ArchMap),
		Syscalls:        merged,
	}
}

type outRule struct {
	Names    []string `json:"names"`
	Action   string   `json:"action"`
	Includes *Cond    `json:"includes,omitempty"`
	Excludes *Cond    `json:"excludes,omitempty"`
	Args     []Arg    `json:"args,omitempty"`
}

type outProfile struct {
	DefaultAction   string      `json:"defaultAction"`
	DefaultErrnoRet *int        `json:"defaultErrnoRet,omitempty"`
	DefaultErrno    *string     `json:"defaultErrno,omitempty"`
	ArchMap         []ArchEntry `json:"archMap"`
	Syscalls        []outRule   `json:"syscalls"`
}

// toJSON builds the canonical, upstream-style profile, regrouping rules that share
// action/args/includes/excludes into one entry with a combined, sorted names list.
func toJSON(p *Profile) (outProfile, error) {
	var groups []*outRule
	index := map[string]*outRule{}
	for _, r := range p.Syscalls {
		g := outRule{Action: r.Action, Includes: r.Includes, Excludes: r.Excludes, Args: r.Args}
		key, err := json.Marshal(g)
		if err != nil {
			return outProfile{}, err
		}
		if index[string(key)] == nil {
			index[string(key)] = &g
			groups = append(groups, &g)
		}
		index[string(key)].Names = append(index[string(key)].Names, r.Name)
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

// validate checks that every allowed syscall is actually allowed by both source profiles.
// It returns human-readable errors; empty means the merge is consistent.
func validate(merged, docker, podman *Profile) []string {
	var errs []string
	if len(merged.Syscalls) == 0 {
		errs = append(errs, "merged profile has no syscall rules")
	}
	dockerRules := allowRulesByName(docker)
	podmanRules := allowRulesByName(podman)
	for _, r := range merged.Syscalls {
		_, inDocker := dockerRules[r.Name]
		_, inPodman := podmanRules[r.Name]
		if !inDocker || !inPodman {
			errs = append(errs, r.Name+": present in output but not allowed by both engines")
		}
	}
	return errs
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
