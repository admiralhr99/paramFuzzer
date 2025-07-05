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
	if len(param) <= 3 && isShortMeaningless(param) {
		return "", false
	}

	// Rule 9: Filter out asset and cache-busting patterns
	if isAssetOrCacheBusting(param) {
		return "", false
	}

	// Rule 10: Filter out generated form IDs and similar patterns
	if isGeneratedFormId(param) {
		return "", false
	}

	// Rule 11: Filter out locale and country code patterns
	if isLocaleOrCountryCode(param) {
		return "", false
	}

	// Rule 12: Filter out common frontend framework patterns
	if isFrontendFrameworkPattern(param) {
		return "", false
	}

	// Rule 13: Filter out HTML element IDs that are clearly not parameters
	if isHTMLElementId(param) {
		return "", false
	}

	// Rule 14: Filter out CSS class patterns
	if isCSSClass(param) {
		return "", false
	}

	// Rule 15: Additional filtering for common non-useful parameters
	if shouldFilterOut(param) {
		return "", false
	}

	// Rule 16: Filter out parameters that are too long (likely not real parameters)
	if len(param) > 100 {
		return "", false
	}

	// Rule 17: Filter out parameters with too many numbers (likely IDs)
	if hasTooManyNumbers(param) {
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
		`^\d+\.\d*[a-z%]*$`,   // CSS values with units
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

	// Container patterns from the output
	patterns := []string{
		`^container-[0-9a-f]{8,}$`, // container-8dbf6e23c2
		`^container-[0-9a-f-]+$`,   // various container patterns
		`^[a-z]+-[0-9a-f]{6,}$`,    // generic-abc123def
		`^[a-z]{1,3}[0-9]+k$`,      // d0k, h3k, etc.
		`^[a-z]{1,2}[0-9]{1,3}$`,   // a1, b2, h3, g17, etc.
		`^[0-9a-f]{8,}$`,           // pure hex strings
		`^uuid-[0-9a-f-]+$`,        // UUID patterns
		`^id-[0-9a-f-]+$`,          // ID patterns
		`^cmp-[0-9a-f-]+$`,         // Component IDs
		`^comp-[0-9a-f-]+$`,        // Component IDs
		`^fgx-[a-z0-9-]+$`,         // Ford framework specific
		`^[a-z]{1,2}[A-Z][0-9]*$`,  // gA, gB7, hA, etc.
		`^[a-z][0-9]{1,3}$`,        // g1, g17, h07, etc.
		`^[A-Z][0-9]{1,3}$`,        // A1, B2, C27, etc.
		`^[A-Z]{1,2}[0-9]+[A-Z]*$`, // D17AA, D2FAK, etc.
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
		`^fgx-[a-z0-9-]+$`,          // Ford framework specific
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isShortMeaningless checks if a short parameter is meaningless
func isShortMeaningless(param string) bool {
	param = strings.ToLower(param)

	// Common meaningless short combinations
	meaningless := []string{
		// Single letters with numbers
		"a1", "a2", "a3", "b1", "b2", "b3", "c1", "c2", "c3",
		"d1", "d2", "d3", "e1", "e2", "e3", "f1", "f2", "f3",
		"g1", "g2", "g3", "h1", "h2", "h3", "i1", "i2", "i3",
		"j1", "j2", "j3", "k1", "k2", "k3", "l1", "l2", "l3",
		"m1", "m2", "m3", "n1", "n2", "n3", "o1", "o2", "o3",
		"p1", "p2", "p3", "q1", "q2", "q3", "r1", "r2", "r3",
		"s1", "s2", "s3", "t1", "t2", "t3", "u1", "u2", "u3",
		"v1", "v2", "v3", "w1", "w2", "w3", "x1", "x2", "x3",
		"y1", "y2", "y3", "z1", "z2", "z3",
		// Common meaningless 2-3 char combinations
		"aa", "ab", "ac", "ad", "ae", "af", "ag", "ah", "ai", "aj",
		"ba", "bb", "bc", "bd", "be", "bf", "bg", "bh", "bi", "bj",
		"ca", "cb", "cc", "cd", "ce", "cf", "cg", "ch", "ci", "cj",
		"da", "db", "dc", "dd", "de", "df", "dg", "dh", "di", "dj",
		"ea", "eb", "ec", "ed", "ee", "ef", "eg", "eh", "ei", "ej",
		"fa", "fb", "fc", "fd", "fe", "ff", "fg", "fh", "fi", "fj",
		"ga", "gb", "gc", "gd", "ge", "gf", "gg", "gh", "gi", "gj",
		"ha", "hb", "hc", "hd", "he", "hf", "hg", "hh", "hi", "hj",
		// Common CSS/HTML meaningless
		"px", "em", "rem", "vh", "vw", "pt", "pc", "in", "cm", "mm",
	}

	for _, meaninglessParam := range meaningless {
		if param == meaninglessParam {
			return true
		}
	}

	// Check patterns for short meaningless params
	patterns := []string{
		`^[a-z][0-9]{1,2}$`, // a1, b17, c3, etc.
		`^[a-z]{2}[0-9]$`,   // ab1, cd2, etc.
		`^[a-z][A-Z]$`,      // aB, cD, etc.
		`^[A-Z]{2,3}$`,      // AB, ABC, etc. (unless they're acronyms)
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isAssetOrCacheBusting checks for asset and cache-busting patterns
func isAssetOrCacheBusting(param string) bool {
	param = strings.ToLower(param)

	patterns := []string{
		`^v[0-9]+$`,         // v1, v2, v100
		`^version[0-9]*$`,   // version, version1
		`^rev[0-9]*$`,       // rev, rev1
		`^build[0-9]*$`,     // build, build1
		`^cache[0-9]*$`,     // cache, cache1
		`^timestamp[0-9]*$`, // timestamp
		`^hash[0-9]*$`,      // hash
		`^[0-9]{10,}$`,      // Unix timestamps
		`^[a-f0-9]{32}$`,    // MD5 hashes
		`^[a-f0-9]{40}$`,    // SHA1 hashes
		`^[a-f0-9]{64}$`,    // SHA256 hashes
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isGeneratedFormId checks for generated form IDs
func isGeneratedFormId(param string) bool {
	patterns := []string{
		`^form-[a-z]+-[0-9]+$`,           // form-button-1049391210
		`^form-[a-z]+-[0-9]{6,}$`,        // form-text-1139535474
		`^[a-z]+-[0-9]{6,}$`,             // Any component with 6+ digit ID
		`^[a-zA-Z]+-[0-9]{8,}$`,          // Any hyphenated 8+ digit ID
		`^general_container_[a-z0-9_]+$`, // general_container_co_493609982
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isLocaleOrCountryCode checks for locale and country code patterns
func isLocaleOrCountryCode(param string) bool {
	param = strings.ToLower(param)

	// Country codes and locale patterns
	patterns := []string{
		`^[a-z]{2}-[a-z]{2}$`,                 // fr-ca, en-us
		`^[a-z]+-content$`,                    // denmark-content
		`^[a-z]+-header$`,                     // denmark-header
		`^[a-z]{2}_[a-z]{2}$`,                 // fr_ca
		`^locale-[a-z]+$`,                     // locale-en
		`^lang-[a-z]+$`,                       // lang-en
		`^country-[a-z]+$`,                    // country-us
		`^[a-z]{2,}-(content|header|footer)$`, // any country with content/header/footer
	}

	// Common country codes and locales
	countryCodes := []string{
		"albania", "algeria", "argentina", "australia", "austria", "bahrain", "belgium",
		"bolivia", "brazil", "bulgaria", "canada", "chile", "china", "colombia", "costarica",
		"croatia", "curacao", "cyprus", "czechrepublic", "denmark", "ecuador", "egypt",
		"elsalvador", "estonia", "ethiopia", "fiji", "finland", "france", "gabon", "georgia",
		"germany", "ghana", "greece", "grenada", "guatemala", "guineaconakry", "haiti",
		"honduras", "hungary", "india", "iraq", "ireland", "israel", "italy", "ivorycoast",
		"jordan", "kazakhstan", "kenya", "kuwait", "latvia", "lebanon", "lithuania",
		"luxembourg", "macedonia", "madagascar", "malaysia", "malta", "mauritius", "mexico",
		"morocco", "netherlands", "newzealand", "nicaragua", "nigeria", "norway", "oman",
		"panama", "paraguay", "peru", "philippines", "poland", "portugal", "qatar",
		"romania", "russia", "saudiarabia", "senegal", "serbia", "singapore", "slovakia",
		"slovenia", "southafrica", "spain", "srilanka", "sweden", "switzerland", "thailand",
		"tunisia", "turkey", "uae", "ukraine", "unitedkingdom", "uruguay", "venezuela",
		"vietnam", "zambia",
	}

	for _, code := range countryCodes {
		if strings.Contains(param, code) {
			return true
		}
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isFrontendFrameworkPattern checks for frontend framework patterns
func isFrontendFrameworkPattern(param string) bool {
	param = strings.ToLower(param)

	patterns := []string{
		`^fpg-[a-z-]+$`,          // Ford Performance Gateway patterns
		`^fgx-[a-z-]+$`,          // Ford framework patterns
		`^ford[a-z]+$`,           // fordMainNavigation, fordPerformance, etc.
		`^lincoln[a-z]+$`,        // Lincoln specific
		`^component-[a-z0-9-]+$`, // Generic component patterns
		`^widget-[a-z0-9-]+$`,    // Widget patterns
		`^module-[a-z0-9-]+$`,    // Module patterns
		`^section-[a-z0-9-]+$`,   // Section patterns
		`^block-[a-z0-9-]+$`,     // Block patterns
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isHTMLElementId checks for HTML element IDs that are clearly not parameters
func isHTMLElementId(param string) bool {
	param = strings.ToLower(param)

	// Common HTML element ID patterns
	patterns := []string{
		`^header[a-z0-9-]*$`,    // header, header-nav, etc.
		`^footer[a-z0-9-]*$`,    // footer, footer-nav, etc.
		`^nav[a-z0-9-]*$`,       // nav, navbar, etc.
		`^sidebar[a-z0-9-]*$`,   // sidebar
		`^content[a-z0-9-]*$`,   // content, content-main
		`^main[a-z0-9-]*$`,      // main, main-content
		`^wrapper[a-z0-9-]*$`,   // wrapper
		`^container[a-z0-9-]*$`, // container
		`^menu[a-z0-9-]*$`,      // menu, menu-main
		`^button[a-z0-9-]*$`,    // button
		`^link[a-z0-9-]*$`,      // link
		`^image[a-z0-9-]*$`,     // image
		`^gallery[a-z0-9-]*$`,   // gallery
		`^slider[a-z0-9-]*$`,    // slider
		`^carousel[a-z0-9-]*$`,  // carousel
		`^modal[a-z0-9-]*$`,     // modal
		`^popup[a-z0-9-]*$`,     // popup
		`^overlay[a-z0-9-]*$`,   // overlay
		`^dialog[a-z0-9-]*$`,    // dialog
		`^banner[a-z0-9-]*$`,    // banner
		`^hero[a-z0-9-]*$`,      // hero
		`^logo[a-z0-9-]*$`,      // logo
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// isCSSClass checks for CSS class patterns
func isCSSClass(param string) bool {
	param = strings.ToLower(param)

	// CSS class patterns
	patterns := []string{
		`^[a-z]+-[0-9]+$`,      // btn-1, col-2, etc.
		`^has-[a-z-]+$`,        // has-children, has-dropdown
		`^is-[a-z-]+$`,         // is-active, is-hidden
		`^show-[a-z-]+$`,       // show-mobile, show-desktop
		`^hide-[a-z-]+$`,       // hide-mobile, hide-desktop
		`^visible-[a-z-]+$`,    // visible-mobile
		`^hidden-[a-z-]+$`,     // hidden-mobile
		`^color-[a-z0-9-]+$`,   // color-red, color-blue
		`^bg-[a-z0-9-]+$`,      // bg-red, bg-blue
		`^text-[a-z0-9-]+$`,    // text-left, text-center
		`^font-[a-z0-9-]+$`,    // font-bold, font-large
		`^border-[a-z0-9-]+$`,  // border-red
		`^margin-[a-z0-9-]+$`,  // margin-top
		`^padding-[a-z0-9-]+$`, // padding-left
		`^flex-[a-z0-9-]+$`,    // flex-grow
		`^grid-[a-z0-9-]+$`,    // grid-col
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, param); matched {
			return true
		}
	}

	return false
}

// hasTooManyNumbers checks if parameter has too many numbers (likely an ID)
func hasTooManyNumbers(param string) bool {
	if len(param) < 4 {
		return false
	}

	numberCount := 0
	for _, char := range param {
		if char >= '0' && char <= '9' {
			numberCount++
		}
	}

	// If more than 60% of the parameter is numbers, it's likely an ID
	if float64(numberCount)/float64(len(param)) > 0.6 {
		return true
	}

	// If it has 6+ consecutive numbers, it's likely an ID
	consecutiveNumbers := 0
	maxConsecutive := 0
	for _, char := range param {
		if char >= '0' && char <= '9' {
			consecutiveNumbers++
			if consecutiveNumbers > maxConsecutive {
				maxConsecutive = consecutiveNumbers
			}
		} else {
			consecutiveNumbers = 0
		}
	}

	return maxConsecutive >= 6
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
		"initial", "unset", "revert", "all", "hidden", "visible", "block",
		"inline", "flex", "grid", "relative", "absolute", "fixed", "static",
		"left", "right", "center", "top", "bottom", "middle",
		"small", "medium", "large", "xl", "xs", "sm", "md", "lg",
		"red", "blue", "green", "yellow", "black", "white", "gray", "grey",
		"dark", "light", "primary", "secondary", "success", "warning", "danger",
		"info", "active", "inactive", "enabled", "disabled", "selected",
		"checked", "unchecked", "expanded", "collapsed", "open", "closed",
		"first", "last", "next", "prev", "previous", "current", "new", "old",
		"edit", "view", "show", "hide", "toggle", "click", "hover", "focus",
		"load", "ready", "change", "submit", "reset", "close", "open",
		"start", "stop", "play", "pause", "end", "begin", "finish",
		"yes", "no", "ok", "cancel", "done", "complete", "continue",
		"home", "back", "forward", "up", "down", "refresh", "reload",
		"save", "delete", "remove", "add", "create", "update", "modify",
		"copy", "paste", "cut", "undo", "redo", "clear", "empty",
		"full", "half", "quarter", "third", "double", "single", "multiple",
		"one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
		// Ford specific non-parameters
		"ford", "lincoln", "vehicle", "car", "truck", "suv", "sedan", "coupe",
		"hybrid", "electric", "gas", "diesel", "engine", "motor", "transmission",
		"dealer", "dealership", "finance", "lease", "buy", "purchase", "price",
		"inventory", "search", "filter", "sort", "compare", "build", "configure",
		"gallery", "image", "photo", "video", "brochure", "manual", "guide",
		"service", "parts", "accessories", "warranty", "maintenance", "repair",
		"appointment", "schedule", "contact", "support", "help", "faq",
		"login", "logout", "register", "account", "profile", "settings",
		"privacy", "terms", "policy", "cookie", "tracking", "analytics",
		"facebook", "twitter", "instagram", "youtube", "linkedin", "social",
		"email", "phone", "address", "location", "map", "directions",
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

	// Meta and tracking patterns
	metaPatterns := []string{
		`^gtm-[a-z0-9]+$`,  // Google Tag Manager
		`^ga-[a-z0-9]+$`,   // Google Analytics
		`^fb-[a-z0-9]+$`,   // Facebook
		`^twitter:[a-z]+$`, // Twitter meta
		`^og:[a-z]+$`,      // Open Graph
		`^datadog[a-z_]*$`, // Datadog
		`^_[a-z]+$`,        // Underscore prefixed (usually private)
	}

	for _, pattern := range metaPatterns {
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
