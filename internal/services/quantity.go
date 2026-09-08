package services

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseQuantity: parses a quantity string into a float64
// supports: "1.5", "1/2", and "1 1/2"
func ParseQuantity(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	var total float64
	for _, part := range strings.Fields(s) {
		if num, den, ok := strings.Cut(part, "/"); ok {
			n, err := strconv.ParseFloat(num, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid quantity %q: %w", s, err)
			}
			d, err := strconv.ParseFloat(den, 64)
			if err != nil || d == 0 {
				return 0, fmt.Errorf("invalid quantity %q", s)
			}
			total += n / d
		} else {
			n, err := strconv.ParseFloat(part, 64)
			if err != nil {
				return 0, fmt.Errorf("invalid quantity %q: %w", s, err)
			}
			total += n
		}
	}
	return total, nil
}

// FormatQuantity: formats a quantity, trimming trailing zeros
func FormatQuantity(q float64) string {
	return strconv.FormatFloat(q, 'f', -1, 64)
}

func CombineQuantities(existingQty, existingUnit, newQty, newUnit string) (qty string, unit string, ok bool) {
	if !strings.EqualFold(strings.TrimSpace(existingUnit), strings.TrimSpace(newUnit)) {
		return newQty, newUnit, false
	}

	existing, err1 := ParseQuantity(existingQty)
	added, err2 := ParseQuantity(newQty)
	if err1 != nil || err2 != nil {
		return newQty, newUnit, false
	}

	return FormatQuantity(existing + added), newUnit, true
}
