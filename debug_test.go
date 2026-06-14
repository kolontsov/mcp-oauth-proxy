package main

import "testing"

func TestLevelFlagSet(t *testing.T) {
	tests := []struct {
		in      string
		want    levelFlag
		wantErr bool
	}{
		{"true", 1, false}, // bare -d
		{"0", 0, false},
		{"3", 3, false},
		{"4", 4, false}, // upper bound
		{"5", 0, true},  // above range
		{"-1", 0, true}, // below range
		{"x", 0, true},  // not a number
	}
	for _, tc := range tests {
		var l levelFlag
		err := l.Set(tc.in)
		if (err != nil) != tc.wantErr {
			t.Errorf("Set(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			continue
		}
		if err == nil && l != tc.want {
			t.Errorf("Set(%q) = %d, want %d", tc.in, l, tc.want)
		}
	}
}

func TestLevelFlagIsBoolFlag(t *testing.T) {
	// IsBoolFlag must report true so the flag package lets bare -d stand alone.
	var l levelFlag
	if !l.IsBoolFlag() {
		t.Error("IsBoolFlag() = false, want true (bare -d must be allowed)")
	}
}
