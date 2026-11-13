package server

import (
	"fmt"
	"os"
	"strings"
)

// interpolate expands the ${{ ... }} expressions in every string value of a
// decoded TOML structure, recursing through nested tables and arrays. Keys
// are left alone. It modifies v in place.
func interpolate(v any) error {
	switch v := v.(type) {
	case map[string]any:
		for key, elem := range v {
			if err := interpolateElem(elem, func(x any) { v[key] = x }); err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
		}
	case []map[string]any: // TOML arrays of tables
		for i, elem := range v {
			if err := interpolate(elem); err != nil {
				return fmt.Errorf("[%d]: %w", i, err)
			}
		}
	case []any:
		for i, elem := range v {
			if err := interpolateElem(elem, func(x any) { v[i] = x }); err != nil {
				return fmt.Errorf("[%d]: %w", i, err)
			}
		}
	}
	return nil
}

// interpolateElem expands a string element through set, or recurses into a
// container element.
func interpolateElem(elem any, set func(any)) error {
	s, ok := elem.(string)
	if !ok {
		return interpolate(elem)
	}
	expanded, err := expand(s)
	if err != nil {
		return err
	}
	set(expanded)
	return nil
}

// expand replaces ${{ env.NAME }} with the environment variable NAME, and
// ${{$}} with a literal "${{". Substituted text is not expanded again.
func expand(s string) (string, error) {
	var out strings.Builder
	for {
		start := strings.Index(s, "${{")
		if start < 0 {
			out.WriteString(s)
			return out.String(), nil
		}
		out.WriteString(s[:start])
		end := strings.Index(s[start:], "}}")
		if end < 0 {
			return "", fmt.Errorf("unterminated %q", s[start:])
		}
		expr := strings.TrimSpace(s[start+len("${{") : start+end])
		s = s[start+end+len("}}"):]

		switch name, isEnv := strings.CutPrefix(expr, "env."); {
		case expr == "$":
			out.WriteString("${{")
		case isEnv:
			value, ok := os.LookupEnv(name)
			if !ok {
				return "", fmt.Errorf("environment variable %s is not set", name)
			}
			out.WriteString(value)
		default:
			return "", fmt.Errorf("unknown expression ${{ %s }}", expr)
		}
	}
}
