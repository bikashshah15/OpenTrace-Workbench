package fixture

import "golang.org/x/text/language"

// Negotiate picks the best supported language for an Accept-Language header.
func Negotiate(header string, supported []string) (string, error) {
	tags, _, err := language.ParseAcceptLanguage(header)
	if err != nil {
		return "", err
	}
	var sup []language.Tag
	for _, s := range supported {
		sup = append(sup, language.Make(s))
	}
	m := language.NewMatcher(sup)
	_, idx, _ := m.Match(tags...)
	return supported[idx], nil
}
