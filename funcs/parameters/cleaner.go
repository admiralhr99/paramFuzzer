package parameters

import (
	"regexp"
	"strconv"
	"strings"
)

// CleanParameter cleans and filters a parameter with minimal false positives
func CleanParameter(param string) (string, bool) {
	param = strings.TrimSpace(param)
	if param == "" {
		return "", false
	}

	// Rule 1: Remove parameters that are purely numbers (but keep hex that might be IDs)
	if isPureDecimalNumber(param) {
		return "", false
	}

	// Rule 2: Remove obvious CSS negative values (very specific patterns)
	if isObviousCSSNegative(param) {
		return "", false
	}

	// Rule 3: Clean CSS custom properties (--property) but keep the property name
	if strings.HasPrefix(param, "--") {
		cleaned := strings.TrimPrefix(param, "--")
		if cleaned != "" && len(cleaned) > 1 {
			return cleaned, true
		}
		return "", false
	}

	// Rule 4: Filter out only very specific container patterns with long hashes
	if isVerySpecificContainerHash(param) {
		return "", false
	}

	// Rule 5: Filter out only very long random-looking hex strings (16+ chars)
	if isVeryLongRandomHex(param) {
		return "", false
	}

	// Rule 6: Filter out only very specific CSS framework patterns
	if isVerySpecificCSSFramework(param) {
		return "", false
	}

	// Rule 7: Filter out only single meaningless characters
	if len(param) == 1 && isSingleMeaninglessChar(param) {
		return "", false
	}

	// Rule 8: Filter out only very specific meaningless short patterns
	if len(param) == 2 && isVerySpecificMeaningless(param) {
		return "", false
	}

	// Rule 9: Filter out only very obvious asset patterns
	if isVeryObviousAssetPattern(param) {
		return "", false
	}

	// Rule 10: Filter out only very specific non-useful patterns
	if isVerySpecificNonUseful(param) {
		return "", false
	}

	// Rule 11: Filter out extremely long parameters (likely not real parameters)
	if len(param) > 150 {
		return "", false
	}

	return param, true
}

// isPureDecimalNumber checks if parameter is purely a decimal number (not hex)
func isPureDecimalNumber(param string) bool {
	if param == "" {
		return false
	}

	// Only filter pure decimal numbers, not hex
	if _, err := strconv.Atoi(param); err == nil {
		// Check if it's not a hex string that happens to be all digits
		if !strings.HasPrefix(strings.ToLower(param), "0x") && len(param) > 2 {
			return true
		}
	}

	return false
}

// isObviousCSSNegative checks for very specific CSS negative values
func isObviousCSSNegative(param string) bool {
	if !strings.HasPrefix(param, "-") {
		return false
	}

	param = strings.ToLower(param)

	// Only very obvious CSS patterns
	patterns := []string{
		`^-\d+px$`,         // -30px, -560px
		`^-\d+deg$`,        // -45deg, -90deg
		`^-\d+%$`,          // -50%, -100%
		`^-\d+em$`,         // -1em, -2em
		`^-\d+rem$`,        // -1rem, -2rem
		`^-webkit-[\w-]+$`, // -webkit-border-radius
		`^-moz-[\w-]+$`,    // -moz-border-radius
		`^-ms-[\w-]+$`,     // -ms-transform
		`^-o-[\w-]+$`,      // -o-transform
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isVerySpecificContainerHash filters only containers with very long hashes
func isVerySpecificContainerHash(param string) bool {
	param = strings.ToLower(param)

	// Only filter containers with long hash-like suffixes (10+ chars)
	patterns := []string{
		`^container-[0-9a-f]{10,}$`,          // container-8dbf6e23c2abc
		`^experiencefragment-[0-9a-f]{10,}$`, // experiencefragment-...
		`^columncard-\d{9,}$`,                // columncard-1234567890
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isVeryLongRandomHex filters only very long hex strings that are clearly random
func isVeryLongRandomHex(param string) bool {
	// Only filter hex strings that are 16+ characters and all hex
	if len(param) >= 16 {
		if matched, _ := regexp.MatchString(`^[0-9a-fA-F]{16,}$`, param); matched {
			return true
		}
	}
	return false
}

// isVerySpecificCSSFramework filters only very specific framework patterns
func isVerySpecificCSSFramework(param string) bool {
	param = strings.ToLower(param)

	// Only very specific framework-generated patterns
	patterns := []string{
		`^css-[0-9a-f]{8,}$`,     // css-12345678 (CSS-in-JS)
		`^sc-[a-z]{6,}$`,         // sc-abcdef (styled-components)
		`^emotion-[0-9a-z]{8,}$`, // emotion-12ab34cd
		`^_[0-9a-f]{8,}$`,        // _12345678 (underscore + long hash)
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isSingleMeaninglessChar filters only single characters that are clearly meaningless
func isSingleMeaninglessChar(param string) bool {
	// Only filter single characters that are clearly not parameters
	meaninglessChars := []string{
		".", ",", ";", ":", "(", ")", "[", "]", "{", "}",
		"<", ">", "/", "\\", "|", "~", "`", "^", "&", "*",
		"+", "=", "?", "!", "@", "#", "$", "%",
	}

	for _, char := range meaninglessChars {
		if param == char {
			return true
		}
	}

	return false
}

// isVerySpecificMeaningless filters only very specific meaningless 2-char patterns
func isVerySpecificMeaningless(param string) bool {
	param = strings.ToLower(param)

	// Only filter very specific patterns that are clearly not parameters
	patterns := []string{
		`^[a-z]\d$`, // Only single letter + single digit (a1, b2, etc.)
	}

	// But keep common meaningful 2-char params like: id, by, to, in, on, at, etc.
	meaningful := []string{
		"id", "by", "to", "in", "on", "at", "if", "or", "of", "as", "is", "do", "go", "no", "up",
		"q", "v", "p", "r", "s", "t", "u", "w", "x", "y", "z", // Single letters can be meaningful
		"qa", "qb", "qc", "qd", "qe", "qf", "qg", "qh", "qi", "qj", "qk", "ql", "qm",
		"qn", "qo", "qp", "qq", "qr", "qs", "qt", "qu", "qv", "qw", "qx", "qy", "qz",
	}

	for _, m := range meaningful {
		if param == m {
			return false // Keep meaningful ones
		}
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isVeryObviousAssetPattern filters only very obvious asset patterns
func isVeryObviousAssetPattern(param string) bool {
	param = strings.ToLower(param)

	// Only very specific asset patterns
	patterns := []string{
		`^v\d{4,}$`,          // v2024, v20241201 (version with year/date)
		`^build\d{8,}$`,      // build20241201
		`^cache\d{8,}$`,      // cache20241201
		`^timestamp\d{10,}$`, // timestamp1234567890
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isVerySpecificNonUseful filters only very specific patterns known to be non-useful
func isVerySpecificNonUseful(param string) bool {
	param = strings.ToLower(param)

	// Only filter very specific patterns that are definitely not useful
	// Remove most of the previous aggressive filtering
	nonUsefulPatterns := []string{
		`^˝œ¸´Ø$`,          // Special characters/encoding issues
		`^˛˘®óøTˇÔƒ≥◊sŸî$`, // Encoding garbage
		`^webkit$`,         // Just "webkit" alone
		`^moz$`,            // Just "moz" alone
		`^xmlns$`,          // XML namespace alone
	}

	for _, pattern := range nonUsefulPatterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// CleanParameterList cleans a list of parameters with minimal filtering
func CleanParameterList(params []string) []string {
	var cleaned []string
	seen := make(map[string]bool)

	for _, param := range params {
		if cleanParam, keep := CleanParameter(param); keep {
			// Case-sensitive deduplication to preserve original casing
			if !seen[cleanParam] {
				cleaned = append(cleaned, cleanParam)
				seen[cleanParam] = true
			}
		}
	}

	return cleaned
}
