// SPDX-License-Identifier: BSD-2-Clause

// Command hardened-seccomp merges Docker's and Podman's default seccomp profiles into one
// that works with both, and prints it to stdout. See merge.go for the policy.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	dockerURL = "https://raw.githubusercontent.com/moby/profiles/main/seccomp/default.json"
	podmanURL = "https://raw.githubusercontent.com/containers/common/main/pkg/seccomp/seccomp.json"
)

// fetch reads JSON text from an http(s) URL or a local file path.
func fetch(source string) ([]byte, error) {
	if !strings.HasPrefix(source, "http://") && !strings.HasPrefix(source, "https://") {
		return os.ReadFile(source)
	}
	client := http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(source)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", source, resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func load(source string) (*Profile, error) {
	data, err := fetch(source)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", source, err)
	}
	p, err := parseProfile(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return p, nil
}

func run() error {
	docker := flag.String("docker", dockerURL, "Docker's profile: URL or file")
	podman := flag.String("podman", podmanURL, "Podman's profile: URL or file")
	flag.Parse()

	d, err := load(*docker)
	if err != nil {
		return err
	}
	p, err := load(*podman)
	if err != nil {
		return err
	}
	merged := merge(d, p)
	if errs := validate(merged, d, p); len(errs) > 0 {
		return fmt.Errorf("validation failed:\n  - %s", strings.Join(errs, "\n  - "))
	}
	out, err := toJSON(merged)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	_, err = os.Stdout.Write(buf.Bytes())
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "hardened-seccomp: %v\n", err)
		os.Exit(1)
	}
}
