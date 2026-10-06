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

func TestValidate(t *testing.T) {
	p := &Profile{Syscalls: []Rule{{Name: "a", Action: actAllow}}}
	none := &Profile{}
	if errs := validate(p, p, p); len(errs) != 0 {
		t.Errorf("unexpected errors: %v", errs)
	}
	if errs := validate(p, p, none); len(errs) != 1 || !strings.HasPrefix(errs[0], "a:") {
		t.Errorf("got %v", errs)
	}
	if errs := validate(none, p, p); len(errs) != 1 {
		t.Errorf("empty merge not reported: %v", errs)
	}
}

// TestGolden merges the snapshots of Docker's and Podman's profiles in testdata and
// compares the result byte for byte with the output of the original Python
// implementation (merge_seccomp.py) on the same input.
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
