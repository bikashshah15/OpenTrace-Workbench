package fixture

import "testing"

func TestNegotiate(t *testing.T) {
	sup := []string{"en", "fr", "de"}
	cases := []struct{ h, want string }{
		{"fr-CH, fr;q=0.9, en;q=0.8", "fr"},
		{"de;q=0.5, en;q=0.9", "en"},
		{"ja", "en"},
		{"", "en"},
		{"de-AT", "de"},
		{"fr;q=0.2, de;q=0.7", "de"},
	}
	for _, c := range cases {
		got, err := Negotiate(c.h, sup)
		if err != nil || got != c.want {
			t.Errorf("Negotiate(%q)=%q,%v want %q", c.h, got, err, c.want)
		}
	}
}
