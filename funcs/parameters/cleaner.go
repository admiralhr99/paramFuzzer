// parameters/cleaner.go - Enhanced parameter cleaning and filtering functions

package parameters

import (
	"regexp"
	"strconv"
	"strings"
)

// CleanParameter cleans and filters a parameter according to enhanced rules
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
		if cleaned != "" && !shouldFilterOut(cleaned) {
			return cleaned, true
		}
		return "", false
	}

	// Rule 4: Filter out container IDs and other hash-based identifiers
	if isContainerOrHashId(param) {
		return "", false
	}

	// Rule 5: Filter out random hexadecimal strings
	if isRandomHexString(param) {
		return "", false
	}

	// Rule 6: Filter out CSS framework artifacts
	if isCSSFrameworkArtifact(param) {
		return "", false
	}

	// Rule 7: Filter out single characters (enhanced)
	if len(param) == 1 {
		return "", false
	}

	// Rule 8: Filter out very short meaningless parameters
	if len(param) == 2 && isShortMeaningless(param) {
		return "", false
	}

	// Rule 9: Filter out asset and cache-busting patterns
	if isAssetOrCacheBusting(param) {
		return "", false
	}

	// Rule 10: Additional filtering for common non-useful parameters
	if shouldFilterOut(param) {
		return "", false
	}

	// Rule 11: Filter out parameters that are too long (likely not real parameters)
	if len(param) > 100 {
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

	withoutMinus := param[1:]
	if withoutMinus == "" {
		return true
	}

	// Enhanced patterns for CSS/numeric values after -
	patterns := []string{
		`^\d+$`,               // Pure numbers: -90, -5, -6
		`^\d+px$`,             // Pixel values: -30px, -560px
		`^\d+[a-zA-Z]+$`,      // Units: -1turn, -1E3
		`^\d+[eE]\d+$`,        // Scientific notation: -1E3
		`^\d+[\-\d]*[\-\d]+$`, // Complex IDs: -7953904435427-31293626450147
		`^[0-9a-f]{6,}$`,      // Hex colors: -ff0000
		`^\d+\.?\d*[a-z%]*$`,  // CSS values with units
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, withoutMinus); matched {
			return true
		}
	}

	return false
}

// isContainerOrHashId checks for container IDs and hash-based identifiers
func isContainerOrHashId(param string) bool {
	param = strings.ToLower(param)

	// Container patterns from your output
	patterns := []string{
		`^container-[0-9a-f]{8,}$`, // container-8dbf6e23c2
		`^container-[0-9a-f-]+$`,   // various container patterns
		`^[a-z]+-[0-9a-f]{6,}$`,    // generic-abc123def
		`^[a-z]{1,3}[0-9]+k$`,      // d0k, h3k, etc.
		`^[a-z]{1,2}[0-9]{1,2}$`,   // a1, b2, h3, etc.
		`^[0-9a-f]{8,}$`,           // pure hex strings
		`^uuid-[0-9a-f-]+$`,        // UUID patterns
		`^id-[0-9a-f-]+$`,          // ID patterns
		`^cmp-[0-9a-f-]+$`,         // Component IDs
		`^comp-[0-9a-f-]+$`,        // Component IDs
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isRandomHexString checks if parameter looks like a random hex string
func isRandomHexString(param string) bool {
	// Check for hex strings of various lengths
	patterns := []string{
		`^[0-9a-fA-F]{8}$`,   // 8 char hex
		`^[0-9a-fA-F]{10}$`,  // 10 char hex
		`^[0-9a-fA-F]{12}$`,  // 12 char hex
		`^[0-9a-fA-F]{16}$`,  // 16 char hex
		`^[0-9a-fA-F]{20,}$`, // 20+ char hex
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isCSSFrameworkArtifact checks for CSS framework generated classes/IDs
func isCSSFrameworkArtifact(param string) bool {
	param = strings.ToLower(param)

	// Framework patterns
	patterns := []string{
		`^css-[0-9a-f]+$`,           // CSS-in-JS hashes
		`^sc-[0-9a-z]+$`,            // Styled components
		`^emotion-[0-9a-z]+$`,       // Emotion CSS
		`^jsx-[0-9]+$`,              // JSX generated
		`^_[0-9a-f]{6,}$`,           // Underscore prefixed hashes
		`^[a-z]+-[a-z]+-[0-9a-f]+$`, // framework-type-hash
		`^react-[0-9a-z-]+$`,        // React specific
		`^angular-[0-9a-z-]+$`,      // Angular specific
		`^vue-[0-9a-z-]+$`,          // Vue specific
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isShortMeaningless checks if a 2-character parameter is meaningless
func isShortMeaningless(param string) bool {
	param = strings.ToLower(param)

	// Common meaningless 2-char combinations
	meaningless := []string{
		"aa", "bb", "cc", "dd", "ee", "ff", "gg", "hh", "ii", "jj",
		"kk", "ll", "mm", "nn", "oo", "pp", "qq", "rr", "ss", "tt",
		"uu", "vv", "ww", "xx", "yy", "zz",
		"0k", "1k", "2k", "3k", "4k", "5k", "6k", "7k", "8k", "9k",
		"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "a8", "a9",
		"b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7", "b8", "b9",
		"c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7", "c8", "c9",
		"d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9",
	}

	for _, meaninglessParam := range meaningless {
		if param == meaninglessParam {
			return true
		}
	}

	// Pattern-based meaningless checks
	patterns := []string{
		`^[a-z][0-9]$`, // Single letter + number
		`^[0-9][a-z]$`, // Number + single letter
		`^[a-z]{2}$`,   // Double letters
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isAssetOrCacheBusting checks for asset references and cache-busting parameters
func isAssetOrCacheBusting(param string) bool {
	param = strings.ToLower(param)

	// Asset and cache patterns
	patterns := []string{
		`^v[0-9]+$`,         // Version numbers: v1, v2
		`^version[0-9]*$`,   // version, version1
		`^rev[0-9]*$`,       // Revision numbers
		`^build[0-9]*$`,     // Build numbers
		`^hash[0-9a-f]*$`,   // Hash parameters
		`^cache[0-9a-f]*$`,  // Cache parameters
		`^timestamp[0-9]*$`, // Timestamp params
		`^ts[0-9]*$`,        // Timestamp short
		`^nocache$`,         // No cache
		`^_[0-9]+$`,         // Underscore + numbers
		`^cb[0-9]+$`,        // Cache buster
		`^r[0-9]+$`,         // Random numbers
		`^t[0-9]+$`,         // Time stamps
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// shouldFilterOut filters out other common non-useful parameters
func shouldFilterOut(param string) bool {
	param = strings.ToLower(param)

	// Static words that are not useful parameters
	staticFilters := []string{
		"a", "an", "the", "and", "or", "but", "in", "on", "at", "to", "for",
		"of", "with", "by", "from", "up", "about", "into", "through", "during",
		"before", "after", "above", "below", "between", "among", "around",
		"container", "content", "data", "item", "element", "component",
		"wrapper", "header", "footer", "main", "nav", "section", "article",
		"aside", "div", "span", "p", "h1", "h2", "h3", "h4", "h5", "h6",
		"ul", "ol", "li", "table", "tr", "td", "th", "thead", "tbody",
		"form", "input", "button", "select", "option", "textarea", "label",
		"img", "svg", "path", "circle", "rect", "line", "polygon",
		"true", "false", "null", "undefined", "none", "auto", "inherit",
		"initial", "unset", "revert", "all",
	}

	for _, filter := range staticFilters {
		if param == filter {
			return true
		}
	}

	// CSS property patterns
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
		`^flex`,
		`^grid`,
		`^justify`,
		`^align`,
	}

	for _, pattern := range cssPatterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	// DOM event patterns
	eventPatterns := []string{
		`^on[a-z]+$`,     // onclick, onload, etc.
		`^handle[a-z]*$`, // handler functions
		`^event[a-z]*$`,  // event related
	}

	for _, pattern := range eventPatterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// CleanParameterList cleans a list of parameters with enhanced deduplication
func CleanParameterList(params []string) []string {
	var cleaned []string
	seen := make(map[string]bool)

	for _, param := range params {
		if cleanParam, keep := CleanParameter(param); keep {
			// Normalize parameter for deduplication (lowercase)
			normalizedParam := strings.ToLower(cleanParam)

			// Avoid duplicates (case-insensitive)
			if !seen[normalizedParam] {
				cleaned = append(cleaned, cleanParam)
				seen[normalizedParam] = true
			}
		}
	}

	return cleaned
}
