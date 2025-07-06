// funcs/parameters/cleaner.go - Complete replacement with strict ASCII rules

package parameters

import (
	"strings"
	"unicode"
)

// CleanParameter cleans and filters a parameter according to strict ASCII rules
func CleanParameter(param string) []string {
	var results []string
	param = strings.TrimSpace(param)

	if param == "" {
		return results
	}

	// Special case: If parameter contains =, split it and process both parts
	if strings.Contains(param, "=") {
		parts := strings.Split(param, "=")
		if len(parts) == 2 {
			// Process the part before =
			if cleanedBefore := processSingleParam(parts[0]); cleanedBefore != "" {
				results = append(results, cleanedBefore)
			}
			// Process the part after =
			if cleanedAfter := processSingleParam(parts[1]); cleanedAfter != "" {
				results = append(results, cleanedAfter)
			}
		}
		return results
	}

	// Process as single parameter
	if cleaned := processSingleParam(param); cleaned != "" {
		results = append(results, cleaned)
	}

	return results
}

// processSingleParam processes a single parameter according to the rules
func processSingleParam(param string) string {
	param = strings.TrimSpace(param)
	if param == "" {
		return ""
	}

	// Rule 1: Remove lines that start without ASCII chars (like !, @, /, etc)
	if !isValidStartChar(rune(param[0])) {
		return ""
	}

	// Rule 2: Remove lines that start with numbers
	if unicode.IsDigit(rune(param[0])) {
		return ""
	}

	// Rule 3: Remove lines that end without ASCII chars (like !, @, /, _, -, etc)
	lastChar := rune(param[len(param)-1])
	if !isValidEndChar(lastChar) {
		return ""
	}

	// Rule 4: Remove lines that contain spaces in between
	if strings.Contains(param, " ") || strings.Contains(param, "\t") {
		return ""
	}

	// Rule 5: Only keep lines that have ASCII chars, numbers, and - _
	// Remove lines that contain . or other special chars
	if !isValidParameterContent(param) {
		return ""
	}

	// Additional filtering: Remove very short or meaningless parameters
	if len(param) < 2 {
		return ""
	}

	// Remove parameters that are too long (likely not real parameters)
	if len(param) > 50 {
		return ""
	}

	// Remove parameters that are purely numbers (already caught by rule 2, but double check)
	if isAllNumbers(param) {
		return ""
	}

	// Remove common non-parameter words
	if isCommonNonParameter(param) {
		return ""
	}

	return param
}

// isValidStartChar checks if a character is valid for starting a parameter
func isValidStartChar(char rune) bool {
	// Must be ASCII letter (a-z, A-Z) or underscore
	return (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || char == '_'
}

// isValidEndChar checks if a character is valid for ending a parameter
func isValidEndChar(char rune) bool {
	// Must be ASCII letter (a-z, A-Z), number (0-9), underscore (_), or hyphen (-)
	return (char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') ||
		char == '_' ||
		char == '-'
}

// isValidParameterContent checks if the entire parameter contains only valid characters
func isValidParameterContent(param string) bool {
	for _, char := range param {
		// Only allow ASCII letters, numbers, underscore, and hyphen
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' ||
			char == '-') {
			return false
		}
	}
	return true
}

// isAllNumbers checks if parameter is purely numeric
func isAllNumbers(param string) bool {
	for _, char := range param {
		if !unicode.IsDigit(char) {
			return false
		}
	}
	return true
}

// isCommonNonParameter filters out common words that are not parameters
func isCommonNonParameter(param string) bool {
	param = strings.ToLower(param)

	// Common non-parameter words
	commonWords := map[string]bool{
		// Basic words
		"a": true, "an": true, "the": true, "and": true, "or": true, "but": true,
		"in": true, "on": true, "at": true, "to": true, "for": true, "of": true,
		"with": true, "by": true, "from": true, "up": true, "about": true,
		"into": true, "through": true, "during": true, "before": true, "after": true,

		// HTML elements
		"div": true, "span": true, "p": true, "h1": true, "h2": true, "h3": true,
		"h4": true, "h5": true, "h6": true, "ul": true, "ol": true, "li": true,
		"table": true, "tr": true, "td": true, "th": true, "thead": true, "tbody": true,
		"form": true, "input": true, "button": true, "select": true, "option": true,
		"textarea": true, "label": true, "img": true, "svg": true, "path": true,

		// Layout words
		"container": true, "content": true, "wrapper": true, "header": true,
		"footer": true, "main": true, "nav": true, "section": true, "article": true,
		"aside": true, "menu": true, "sidebar": true,

		// Common CSS/JS words
		"hidden": true, "visible": true, "block": true, "inline": true, "flex": true,
		"grid": true, "relative": true, "absolute": true, "fixed": true, "static": true,
		"left": true, "right": true, "center": true, "top": true, "bottom": true,
		"active": true, "inactive": true, "disabled": true, "enabled": true,
		"selected": true, "checked": true, "expanded": true, "collapsed": true,

		// Colors and sizes
		"red": true, "blue": true, "green": true, "yellow": true, "black": true,
		"white": true, "gray": true, "grey": true, "dark": true, "light": true,
		"small": true, "medium": true, "large": true, "xl": true, "xs": true,
		"sm": true, "md": true, "lg": true,

		// Actions
		"show": true, "hide": true, "toggle": true, "click": true, "hover": true,
		"focus": true, "load": true, "ready": true, "change": true, "submit": true,
		"reset": true, "close": true, "open": true, "start": true, "stop": true,
		"play": true, "pause": true, "end": true, "begin": true, "finish": true,

		// Boolean/Status
		"true": true, "false": true, "null": true, "undefined": true, "none": true,
		"auto": true, "inherit": true, "initial": true, "unset": true, "revert": true,
		"yes": true, "no": true, "ok": true, "cancel": true, "done": true,

		// Common operations
		"edit": true, "view": true, "save": true, "delete": true, "remove": true,
		"add": true, "create": true, "update": true, "modify": true, "copy": true,
		"paste": true, "cut": true, "undo": true, "redo": true, "clear": true,

		// Ford/Automotive specific (adjust as needed)
		"ford": true, "lincoln": true, "vehicle": true, "car": true, "truck": true,
		"suv": true, "sedan": true, "coupe": true, "hybrid": true, "electric": true,
		"gas": true, "diesel": true, "engine": true, "motor": true,

		// Programming terms
		"function": true, "return": true, "var": true, "let": true, "const": true,
		"if": true, "else": true, "while": true, "do": true,
		"switch": true, "case": true, "break": true, "continue": true,
		"try": true, "catch": true, "finally": true, "throw": true,
		"class": true, "extends": true, "import": true, "export": true,
		"async": true, "await": true, "new": true, "this": true,

		// Framework terms
		"react": true, "vue": true, "angular": true, "jquery": true,
		"bootstrap": true, "component": true, "props": true, "state": true,
		"render": true, "mount": true, "unmount": true, "lifecycle": true,
	}

	return commonWords[param]
}

// CleanParameterList cleans a list of parameters and handles = splitting
func CleanParameterList(params []string) []string {
	var cleaned []string
	seen := make(map[string]bool)

	for _, param := range params {
		// CleanParameter now returns a slice (handles = splitting)
		cleanedParams := CleanParameter(param)

		for _, cleanParam := range cleanedParams {
			if cleanParam != "" {
				// Normalize for deduplication (lowercase)
				normalized := strings.ToLower(cleanParam)

				// Avoid duplicates (case-insensitive)
				if !seen[normalized] {
					cleaned = append(cleaned, cleanParam)
					seen[normalized] = true
				}
			}
		}
	}

	return cleaned
}

// JavaScript dangerous sinks for suspicious parameter detection
var JS_CODE_EXECUTION = []string{"eval", "function", "settimeout", "setinterval", "execscript", "compile", "execute", "run", "execcommand", "createfunction"}
var JS_DOM_MANIPULATION = []string{"innerhtml", "outerhtml", "insertadjacenthtml", "document", "write", "writeln", "createelement", "appendchild", "insertbefore", "replacechild"}
var JS_SCRIPT_INJECTION = []string{"script", "javascript", "src", "href", "action", "formaction", "background", "lowsrc", "data", "value", "content"}
var JS_DYNAMIC_IMPORT = []string{"import", "require", "load", "include", "module", "plugin", "component", "loadmodule", "importscripts"}
var JS_TEMPLATE_ENGINE = []string{"template", "render", "compile", "mustache", "handlebars", "ejs", "pug", "vue", "angular", "react", "jsx"}
var JS_EVENT_HANDLERS = []string{"onclick", "onload", "onerror", "onmouseover", "onfocus", "onblur", "onchange", "onsubmit", "onmouseout", "onkeydown", "onkeyup"}
var JS_NAVIGATION = []string{"location", "redirect", "href", "assign", "replace", "reload", "open", "close", "navigate", "pushstate", "replacestate"}
var JS_ATTRIBUTE_SINKS = []string{"style", "class", "id", "name", "title", "alt", "placeholder", "pattern", "formnovalidate"}
var JS_URL_SINKS = []string{"url", "uri", "link", "path", "route", "endpoint", "api", "callback", "jsonp", "websocket"}
var JS_JSON_SINKS = []string{"json", "parse", "stringify", "data", "response", "payload", "config", "options", "params"}

// Maps to store JavaScript dangerous sinks
var jsDangerousSinkMap map[string]string

func init() {
	// Initialize the map for JavaScript dangerous sinks
	jsDangerousSinkMap = make(map[string]string)

	for _, param := range JS_CODE_EXECUTION {
		jsDangerousSinkMap[param] = "JS_CODE_EXEC"
	}
	for _, param := range JS_DOM_MANIPULATION {
		jsDangerousSinkMap[param] = "JS_DOM_MANIP"
	}
	for _, param := range JS_SCRIPT_INJECTION {
		jsDangerousSinkMap[param] = "JS_SCRIPT_INJ"
	}
	for _, param := range JS_DYNAMIC_IMPORT {
		jsDangerousSinkMap[param] = "JS_DYN_IMPORT"
	}
	for _, param := range JS_TEMPLATE_ENGINE {
		jsDangerousSinkMap[param] = "JS_TEMPLATE"
	}
	for _, param := range JS_EVENT_HANDLERS {
		jsDangerousSinkMap[param] = "JS_EVENT"
	}
	for _, param := range JS_NAVIGATION {
		jsDangerousSinkMap[param] = "JS_NAVIGATION"
	}
	for _, param := range JS_ATTRIBUTE_SINKS {
		jsDangerousSinkMap[param] = "JS_ATTRIBUTE"
	}
	for _, param := range JS_URL_SINKS {
		jsDangerousSinkMap[param] = "JS_URL"
	}
	for _, param := range JS_JSON_SINKS {
		jsDangerousSinkMap[param] = "JS_JSON"
	}
}

// IsSusParameter determines if a parameter is a JavaScript dangerous sink
func IsSusParameter(param string) (bool, string) {
	paramLower := strings.ToLower(param)

	// Check for exact matches first
	if vulnType, exists := jsDangerousSinkMap[paramLower]; exists {
		return true, vulnType
	}

	// Check for partial matches for JavaScript dangerous sinks
	for sink, vulnType := range jsDangerousSinkMap {
		if strings.Contains(paramLower, sink) || strings.Contains(sink, paramLower) {
			return true, vulnType
		}
	}

	return false, ""
}
