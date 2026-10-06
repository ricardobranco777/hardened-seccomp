// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
)

func eq(index uint, v uint64) Arg { return Arg{Index: index, Value: v, Op: opEQ} }
func arg(op string, v uint64) Arg { return Arg{Value: v, Op: op} }

func TestReduceComparisons(t *testing.T) {
	tests := []struct {
		name string
		in   []Arg
		want []Arg
		ok   bool
	}{
		{"eq and eq same", []Arg{arg(opEQ, 3), arg(opEQ, 3)}, []Arg{eq(0, 3)}, true},
		{"eq and eq differ", []Arg{arg(opEQ, 3), arg(opEQ, 4)}, nil, false},
		{"eq inside range", []Arg{arg(opGE, 1), arg(opEQ, 3)}, []Arg{eq(0, 3)}, true},
		{"eq outside range", []Arg{arg(opLT, 3), arg(opEQ, 3)}, nil, false},
		{"eq and ne same", []Arg{arg(opEQ, 3), arg(opNE, 3)}, nil, false},
		{"lt zero", []Arg{arg(opLT, 0)}, nil, false},
		{"gt max", []Arg{arg(opGT, math.MaxUint64)}, nil, false},
		{"le and ge meet", []Arg{arg(opLE, 5), arg(opGE, 5)}, []Arg{eq(0, 5)}, true},
		{"ne inside range kept", []Arg{arg(opGE, 1), arg(opNE, 2)}, []Arg{arg(opGE, 1), arg(opNE, 2)}, true},
		{"ne outside range dropped", []Arg{arg(opLE, 5), arg(opNE, 9)}, []Arg{arg(opLE, 5)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := reduceComparisons(0, tt.in)
			if ok != tt.ok || !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, %v; want %v, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestCombineArgs(t *testing.T) {
	mask := Arg{Index: 0, Value: 0xff, Op: opMaskedEQ}
	// socket(): Docker restricts the address family (arg 0), Podman the netlink protocol
	// (arg 2); both have to hold.
	got, ok := combineArgs([]Arg{eq(0, 16), eq(2, 9), eq(0, 16)})
	if want := []Arg{eq(0, 16), eq(2, 9)}; !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, %v; want %v", got, ok, want)
	}
	if _, ok := combineArgs([]Arg{eq(0, 1), eq(0, 2)}); ok {
		t.Error("contradictory args combined")
	}
	got, ok = combineArgs([]Arg{mask, eq(0, 1)})
	if want := []Arg{eq(0, 1), mask}; !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("masked comparison not kept after plain ones: got %v, %v", got, ok)
	}
}

func TestIntersectRules(t *testing.T) {
	rule := func(inc, exc *Cond, args ...Arg) Rule {
		return Rule{Name: "x", Action: actAllow, Includes: inc, Excludes: exc, Args: args}
	}
	t.Run("caps required by both", func(t *testing.T) {
		r, ok := intersectRules("x", rule(&Cond{Caps: []string{"CAP_B"}}, nil), rule(&Cond{Caps: []string{"CAP_A"}}, nil))
		if !ok || !reflect.DeepEqual(r.Includes.Caps, []string{"CAP_A", "CAP_B"}) {
			t.Errorf("got %+v, %v", r, ok)
		}
	})
	t.Run("required cap excluded by other", func(t *testing.T) {
		_, ok := intersectRules("x", rule(&Cond{Caps: []string{"CAP_A"}}, nil), rule(nil, &Cond{Caps: []string{"CAP_A"}}))
		if ok {
			t.Error("expected no rule")
		}
	})
	t.Run("arches intersect minus excludes", func(t *testing.T) {
		a := rule(&Cond{Arches: []string{"amd64", "arm64", "s390x"}}, nil)
		b := rule(&Cond{Arches: []string{"amd64", "s390x"}}, &Cond{Arches: []string{"s390x"}})
		r, ok := intersectRules("x", a, b)
		if !ok || !reflect.DeepEqual(r.Includes.Arches, []string{"amd64"}) || r.Excludes != nil {
			t.Errorf("got %+v, %v", r, ok)
		}
	})
	t.Run("no common arch", func(t *testing.T) {
		_, ok := intersectRules("x", rule(&Cond{Arches: []string{"amd64"}}, nil), rule(&Cond{Arches: []string{"arm64"}}, nil))
		if ok {
			t.Error("expected no rule")
		}
	})
	t.Run("newer kernel wins", func(t *testing.T) {
		r, _ := intersectRules("x", rule(&Cond{MinKernel: "4.8"}, nil), rule(&Cond{MinKernel: "5.10"}, nil))
		if r.Includes.MinKernel != "5.10" { // not a string comparison
			t.Errorf("got %q", r.Includes.MinKernel)
		}
	})
	t.Run("contradictory args", func(t *testing.T) {
		if _, ok := intersectRules("x", rule(nil, nil, eq(0, 1)), rule(nil, nil, eq(0, 2))); ok {
			t.Error("expected no rule")
		}
	})
}

func TestDropRedundant(t *testing.T) {
	plain := Rule{Name: "x", Action: actAllow}
	gated := Rule{Name: "x", Action: actAllow, Includes: &Cond{Caps: []string{"CAP_A"}}}
	args := Rule{Name: "x", Action: actAllow, Args: []Arg{eq(0, 1)}}

	if got := dropRedundant([]Rule{gated, plain}); !reflect.DeepEqual(got, []Rule{plain}) {
		t.Errorf("gated rule not covered by unconditional one: %v", got)
	}
	if got := dropRedundant([]Rule{args, plain}); !reflect.DeepEqual(got, []Rule{plain}) {
		t.Errorf("arg rule not covered by unconditional one: %v", got)
	}
	if got := dropRedundant([]Rule{plain, plain}); len(got) != 1 {
		t.Errorf("duplicates should collapse to one: %v", got)
	}
	if got := dropRedundant([]Rule{gated, args}); len(got) != 2 {
		t.Errorf("unrelated rules should both stay: %v", got)
	}
}

func TestParseProfileRejectsUnknown(t *testing.T) {
	for name, in := range map[string]string{
		"includes":           `{"includes": {"foo": 1}}`,
		"excludes minKernel": `{"excludes": {"minKernel": "4.8"}}`,
		"arg field":          `{"args": [{"index": 0, "value": 1, "op": "SCMP_CMP_EQ", "foo": 1}]}`,
		"bad kernel":         `{"includes": {"minKernel": "x"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			data := `{"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [{"names": ["a"], "action": "SCMP_ACT_ALLOW", ` +
				in[1:len(in)-1] + `}]}`
			if _, err := parseProfile([]byte(data)); err == nil {
				t.Error("no error")
			}
		})
	}
}

func TestParseProfileSplitsNames(t *testing.T) {
	p, err := parseProfile([]byte(`{"defaultAction": "SCMP_ACT_ERRNO", "syscalls": [
		{"names": ["a", "b"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 0, "value": 1, "valueTwo": 0, "op": "SCMP_CMP_EQ"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Syscalls) != 2 || p.Syscalls[1].Name != "b" || !reflect.DeepEqual(p.Syscalls[1].Args, []Arg{eq(0, 1)}) {
		t.Errorf("got %+v", p.Syscalls)
	}
}

func TestUnionArchMaps(t *testing.T) {
	var a, b []ArchEntry
	_ = json.Unmarshal([]byte(`[{"architecture": "X", "subArchitectures": ["B"]}, {"architecture": "Z", "subArchitectures": null}]`), &a)
	_ = json.Unmarshal([]byte(`[{"architecture": "X", "subArchitectures": ["A", "B"]}, {"architecture": "Y"}]`), &b)
	out, _ := json.Marshal(unionArchMaps(a, b))
	want := `[{"architecture":"X","subArchitectures":["A","B"]},{"architecture":"Z","subArchitectures":null},{"architecture":"Y"}]`
	if string(out) != want {
		t.Errorf("got %s", out)
	}
}

// prof parses a profile with ENOSYS as the default errno (Podman's) and these syscall rules.
func prof(t *testing.T, rules ...string) *Profile {
	t.Helper()
	p, err := parseProfile([]byte(`{"defaultAction": "SCMP_ACT_ERRNO", "defaultErrnoRet": 38, "syscalls": [` +
		strings.Join(rules, ",") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// mergeDump merges and returns the rules of the result as compact JSON, in output order.
func mergeDump(t *testing.T, docker, podman *Profile) []string {
	t.Helper()
	merged := merge(docker, podman)
	if errs := validate(merged, docker, podman); len(errs) > 0 {
		t.Fatal(errs)
	}
	out, err := toJSON(merged)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, r := range out.Syscalls {
		b, _ := json.Marshal(r)
		lines = append(lines, string(b))
	}
	return lines
}

func checkRules(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

const (
	allow      = `"action": "SCMP_ACT_ALLOW"`
	eperm      = `"action": "SCMP_ACT_ERRNO", "errnoRet": 1, "errno": "EPERM"`
	enosys     = `"action": "SCMP_ACT_ERRNO", "errnoRet": 38`
	capSysAdm  = `{"caps": ["CAP_SYS_ADMIN"]}`
	capPerfmon = `{"caps": ["CAP_PERFMON"]}`
)

func rule(names, fields string) string { return `{"names": [` + names + `], ` + fields + `}` }

// A syscall only one engine has rules for keeps them: the other engine's silence is not a deny.
func TestMergeOnlyOneEngine(t *testing.T) {
	docker := prof(t, rule(`"mseal"`, allow), rule(`"lsm"`, allow+`, "includes": `+capSysAdm))
	podman := prof(t, rule(`"kexec_load"`, eperm), rule(`"keyctl"`, allow))
	checkRules(t, mergeDump(t, docker, podman),
		`{"names":["kexec_load"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"errno":"EPERM"}`,
		`{"names":["keyctl","mseal"],"action":"SCMP_ACT_ALLOW"}`,
		`{"names":["lsm"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_SYS_ADMIN"]}}`)
}

// One engine allowing and the other denying outright: denied, with the denier's errno.
func TestMergeDenyWins(t *testing.T) {
	docker := prof(t, rule(`"vmsplice"`, allow))
	podman := prof(t, rule(`"vmsplice"`, eperm))
	checkRules(t, mergeDump(t, docker, podman),
		`{"names":["vmsplice"],"action":"SCMP_ACT_ERRNO","errnoRet":1,"errno":"EPERM"}`)
}

// setns: Docker allows with CAP_SYS_ADMIN; Podman allows and then denies without it. The
// ALLOW keeps the cap and Podman's EPERM stays, so nothing overlaps.
func TestMergeKeepsDeny(t *testing.T) {
	docker := prof(t, rule(`"setns"`, allow+`, "includes": `+capSysAdm))
	podman := prof(t, rule(`"setns"`, allow), rule(`"setns"`, eperm+`, "excludes": `+capSysAdm))
	checkRules(t, mergeDump(t, docker, podman),
		`{"names":["setns"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_SYS_ADMIN"]}}`,
		`{"names":["setns"],"action":"SCMP_ACT_ERRNO","excludes":{"caps":["CAP_SYS_ADMIN"]},"errnoRet":1,"errno":"EPERM"}`)
}

// perf_event_open: Podman allows with CAP_PERFMON but denies without CAP_SYS_ADMIN, which
// overlap. The deny wins, so the ALLOW has to require CAP_SYS_ADMIN as well.
func TestMergeNarrowsAllowToDeny(t *testing.T) {
	docker := prof(t, rule(`"perf_event_open"`, allow+`, "includes": `+capPerfmon))
	podman := prof(t, rule(`"perf_event_open"`, allow+`, "includes": `+capPerfmon),
		rule(`"perf_event_open"`, eperm+`, "excludes": `+capSysAdm))
	checkRules(t, mergeDump(t, docker, podman),
		`{"names":["perf_event_open"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_PERFMON","CAP_SYS_ADMIN"]}}`,
		`{"names":["perf_event_open"],"action":"SCMP_ACT_ERRNO","excludes":{"caps":["CAP_SYS_ADMIN"]},"errnoRet":1,"errno":"EPERM"}`)
}

// socket: the Podman rules that differ only in CAP_AUDIT_WRITE collapse into one.
func TestMergeCollapsesComplementaryCaps(t *testing.T) {
	docker := prof(t, rule(`"socket"`, allow+`, "args": [{"index": 0, "value": 10, "op": "SCMP_CMP_EQ"}]`))
	podman := prof(t, rule(`"socket"`, allow+`, "excludes": {"caps": ["CAP_AUDIT_WRITE"]}`),
		rule(`"socket"`, allow+`, "includes": {"caps": ["CAP_AUDIT_WRITE"]}`))
	checkRules(t, mergeDump(t, docker, podman),
		`{"names":["socket"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":10,"op":"SCMP_CMP_EQ"}]}`)
}

// A deny with the default action is dropped: libseccomp rejects it and it changes nothing.
func TestMergeDropsDefaultDeny(t *testing.T) {
	docker := prof(t, rule(`"clone3"`, allow+`, "includes": `+capSysAdm),
		rule(`"clone3"`, enosys+`, "excludes": `+capSysAdm))
	podman := prof(t, rule(`"clone3"`, allow))
	checkRules(t, mergeDump(t, docker, podman),
		`{"names":["clone3"],"action":"SCMP_ACT_ALLOW","includes":{"caps":["CAP_SYS_ADMIN"]}}`)
}

func TestValidate(t *testing.T) {
	p := prof(t, rule(`"a"`, allow))
	deny := prof(t, rule(`"a"`, eperm))
	none := prof(t)
	if errs := validate(p, p, p); len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if errs := validate(p, p, none); len(errs) != 0 {
		t.Errorf("a syscall one engine doesn't mention is fine: %v", errs)
	}
	if errs := validate(p, p, deny); len(errs) != 1 || !strings.Contains(errs[0], "denied by Podman") {
		t.Errorf("got %v", errs)
	}
	if errs := validate(none, p, p); len(errs) != 1 {
		t.Errorf("empty merge not reported: %v", errs)
	}
	overlap := prof(t, rule(`"a"`, allow), rule(`"a"`, eperm+`, "excludes": `+capSysAdm))
	if errs := validate(overlap, p, p); len(errs) != 1 || !strings.Contains(errs[0], "overlap") {
		t.Errorf("overlapping allow and deny not reported: %v", errs)
	}
	disjoint := prof(t, rule(`"a"`, allow+`, "includes": `+capSysAdm), rule(`"a"`, eperm+`, "excludes": `+capSysAdm))
	if errs := validate(disjoint, p, p); len(errs) != 0 {
		t.Errorf("disjoint rules rejected: %v", errs)
	}
}

// TestGolden merges the snapshots of Docker's and Podman's profiles in testdata and
// compares the result byte for byte with testdata/hardened-seccomp.json. After changing the
// policy, regenerate it with:
//
//	go run . -docker testdata/docker.json -podman testdata/podman.json > testdata/hardened-seccomp.json
func TestGolden(t *testing.T) {
	load := func(path string) *Profile {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		p, err := parseProfile(data)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	docker, podman := load("testdata/docker.json"), load("testdata/podman.json")
	merged := merge(docker, podman)
	if errs := validate(merged, docker, podman); len(errs) > 0 {
		t.Fatal(errs)
	}
	out, err := toJSON(merged)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/hardened-seccomp.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Error("output differs from testdata/hardened-seccomp.json")
	}
}
