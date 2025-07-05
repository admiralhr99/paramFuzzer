// parameters/cleaner.go - Parameter cleaning and filtering functions

package parameters

import (
	"regexp"
	"strconv"
	"strings"
)

// CleanParameter cleans and filters a parameter according to the rules
func CleanParameter(param string) (string, bool) {
	param = strings.TrimSpace(param)
	if param == "" {
		return "", false
	}

	// Rule 1: Remove parameters that are purely numbers
	if isPureNumber(param) {
		return "", false
	}

	// Rule 2: Remove parameters starting with - followed by numbers/CSS values
	if shouldRemoveNegativeParam(param) {
		return "", false
	}

	// Rule 3: Clean parameters starting with -- (remove the prefix)
	if strings.HasPrefix(param, "--") {
		cleaned := strings.TrimPrefix(param, "--")
		if cleaned != "" {
			return cleaned, true
		}
		return "", false
	}

	// Rule 4: Additional filtering for common non-useful parameters
	if shouldFilterOut(param) {
		return "", false
	}

	return param, true
}

// isPureNumber checks if a parameter is purely numeric
func isPureNumber(param string) bool {
	if param == "" {
		return false
	}

	// Try to parse as integer
	if _, err := strconv.Atoi(param); err == nil {
		return true
	}

	// Try to parse as float
	if _, err := strconv.ParseFloat(param, 64); err == nil {
		return true
	}

	return false
}

// shouldRemoveNegativeParam checks if parameter starts with - followed by numbers/CSS values
func shouldRemoveNegativeParam(param string) bool {
	if !strings.HasPrefix(param, "-") {
		return false
	}

	// Remove the leading -
	withoutMinus := param[1:]
	if withoutMinus == "" {
		return true
	}

	// Pattern for CSS/numeric values after -
	patterns := []string{
		`^\d+$`,               // Pure numbers: -90, -5, -6
		`^\d+px$`,             // Pixel values: -30px, -560px
		`^\d+[a-zA-Z]+$`,      // Units: -1turn, -1E3
		`^\d+[eE]\d+$`,        // Scientific notation: -1E3
		`^\d+[\-\d]*[\-\d]+$`, // Complex IDs: -7953904435427-31293626450147
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, withoutMinus); matched {
			return true
		}
	}

	return false
}

// shouldFilterOut filters out other common non-useful parameters
func shouldFilterOut(param string) bool {
	param = strings.ToLower(param)

	// Filter out common CSS/styling parameters that aren't useful for security testing
	cssPatterns := []string{
		`^color$`,
		`^background`,
		`^border`,
		`^margin`,
		`^padding`,
		`^font`,
		`^width$`,
		`^height$`,
		`^top$`,
		`^left$`,
		`^right$`,
		`^bottom$`,
		`^position$`,
		`^display$`,
		`^opacity$`,
		`^transform$`,
		`^transition$`,
		`^animation`,
		`^text-`,
		`^line-height$`,
		`^letter-spacing$`,
		`^word-spacing$`,
		`^vertical-align$`,
		`^z-index$`,
		`^overflow`,
		`^visibility$`,
		`^cursor$`,
		`^outline`,
		`^box-shadow$`,
		`^text-shadow$`,
		`^filter$`,
		`^backdrop-filter$`,
	}

	for _, pattern := range cssPatterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	// Filter out very short parameters (1-2 characters) that are likely not meaningful
	if len(param) <= 2 {
		return true
	}

	return false
}

// CleanParameterList cleans a list of parameters
func CleanParameterList(params []string) []string {
	var cleaned []string
	seen := make(map[string]bool)

	for _, param := range params {
		if cleanParam, keep := CleanParameter(param); keep {
			// Avoid duplicates
			if !seen[cleanParam] {
				cleaned = append(cleaned, cleanParam)
				seen[cleanParam] = true
			}
		}
	}

	return cleaned
}
