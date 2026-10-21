package portspec

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"80", []int{80}},
		{"80,443,8080", []int{80, 443, 8080}},
		{"8000-8003", []int{8000, 8001, 8002, 8003}},
		{"443,80,443", []int{80, 443}},
		{"80, 443 , 8000-8001", []int{80, 443, 8000, 8001}},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.in, err)
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("Parse(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, in := range []string{"", "abc", "70000", "0", "100-10", "80-"} {
		if _, err := Parse(in); err == nil {
			t.Fatalf("Parse(%q) expected error", in)
		}
	}
}
