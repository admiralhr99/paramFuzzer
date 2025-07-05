// parameters/find.go - Enhanced parameter extraction with improved patterns

package parameters

import (
	"encoding/json"
	"net/url"
	"strings"

	"github.com/admiralhr99/paramFuzzer/funcs/utils"
)

// Find extracts parameters from body content with enhanced patterns
func Find(link, body, cnHeader string) []string {
	var result []string
	var allParameter []string

	// Parse URL parameters
	if parsedURL, err := url.Parse(link); err == nil {
		for key := range parsedURL.Query() {
			allParameter = append(allParameter, key)
		}
	}

	// Enhanced JavaScript variable patterns
	jsVarPatterns := []string{
		// Standard variable declarations
		`(?:var|let|const)\s+([a-zA-Z_\$][a-zA-Z0-9_\$]*)\s*=`,
		// Object property assignments
		`([a-zA-Z_\$][a-zA-Z0-9_\$]*)\s*[:=]\s*["'\x60]`,
		// Function parameters
		`function\s+[a-zA-Z_\$][a-zA-Z0-9_\$]*\s*\(\s*([a-zA-Z_\$][a-zA-Z0-9_\$]*(?:\s*,\s*[a-zA-Z_\$][a-zA-Z0-9_\$]*)*)\s*\)`,
		// Arrow function parameters
		`(?:const|let|var)\s+[a-zA-Z_\$][a-zA-Z0-9_\$]*\s*=\s*\(\s*([a-zA-Z_\$][a-zA-Z0-9_\$]*(?:\s*,\s*[a-zA-Z_\$][a-zA-Z0-9_\$]*)*)\s*\)\s*=>`,
		// Object destructuring
		`(?:const|let|var)\s*\{\s*([a-zA-Z_\$][a-zA-Z0-9_\$]*(?:\s*,\s*[a-zA-Z_\$][a-zA-Z0-9_\$]*)*)\s*\}\s*=`,
		// Array destructuring
		`(?:const|let|var)\s*\[\s*([a-zA-Z_\$][a-zA-Z0-9_\$]*(?:\s*,\s*[a-zA-Z_\$][a-zA-Z0-9_\$]*)*)\s*\]\s*=`,
	}

	for _, pattern := range jsVarPatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		for _, match := range matches {
			// Split comma-separated parameters
			if strings.Contains(match, ",") {
				parts := strings.Split(match, ",")
				for _, part := range parts {
					part = strings.TrimSpace(part)
					if part != "" {
						allParameter = append(allParameter, part)
					}
				}
			} else {
				allParameter = append(allParameter, match)
			}
		}
	}

	// Enhanced API endpoint patterns
	apiPatterns := []string{
		// REST API paths with parameters
		`["'\x60]/api/[^"'\x60]*\{([a-zA-Z_][a-zA-Z0-9_]*)\}[^"'\x60]*["'\x60]`,
		`["'\x60]/v\d+/[^"'\x60]*\{([a-zA-Z_][a-zA-Z0-9_]*)\}[^"'\x60]*["'\x60]`,
		// GraphQL queries
		`query[^{]*\{[^}]*([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)`,
		// AJAX/fetch calls with parameters
		`\.(?:get|post|put|delete|patch)\s*\(\s*["'\x60][^"'\x60]*["'\x60]\s*,\s*\{[^}]*([a-zA-Z_][a-zA-Z0-9_]*)\s*:`,
	}

	for _, pattern := range apiPatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		allParameter = append(allParameter, matches...)
	}

	// Enhanced URL parameter extraction
	urlParamPatterns := []string{
		// Query parameters in various formats
		`[?&]([a-zA-Z_][a-zA-Z0-9_]*)\s*=`,
		`[?&]([a-zA-Z_][a-zA-Z0-9_]*)\s*:`,
		// URL templates
		`\{([a-zA-Z_][a-zA-Z0-9_]*)\}`,
		// Path parameters
		`:([a-zA-Z_][a-zA-Z0-9_]*)`,
		// Angular/Vue router parameters
		`\/\:([a-zA-Z_][a-zA-Z0-9_]*)`,
	}

	for _, pattern := range urlParamPatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		allParameter = append(allParameter, matches...)
	}

	// Enhanced JSON extraction
	jsonPatterns := []string{
		// JSON object keys with various quote types
		`["']([a-zA-Z_][a-zA-Z0-9_]*)["']:\s*["'\{\[]`,
		`([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*["'\{\[]`,
		// JSON in script tags
		`<script[^>]*>\s*(?:var|let|const)\s+[a-zA-Z_\$][a-zA-Z0-9_\$]*\s*=\s*(\{[^}]*\})`,
	}

	for _, pattern := range jsonPatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		for _, match := range matches {
			// Try to parse JSON and extract keys
			if keys := extractJSONKeys(match); len(keys) > 0 {
				allParameter = append(allParameter, keys...)
			} else {
				allParameter = append(allParameter, match)
			}
		}
	}

	// Enhanced form field extraction
	formPatterns := []string{
		// Input fields with name attribute
		`<input[^>]+name\s*=\s*["']([^"']+)["']`,
		// Input fields with id attribute
		`<input[^>]+id\s*=\s*["']([^"']+)["']`,
		// Select fields
		`<select[^>]+name\s*=\s*["']([^"']+)["']`,
		// Textarea fields
		`<textarea[^>]+name\s*=\s*["']([^"']+)["']`,
		// Form data in JavaScript
		`(?:FormData|URLSearchParams)[^}]*["']([a-zA-Z_][a-zA-Z0-9_]*)["']`,
		// React form libraries
		`register\s*\(\s*["']([a-zA-Z_][a-zA-Z0-9_]*)["']`,
	}

	if !strings.Contains(cnHeader, "javascript") {
		for _, pattern := range formPatterns {
			matches := utils.MyRegex(pattern, body, []int{1})
			allParameter = append(allParameter, matches...)
		}
	}

	// Enhanced data attribute extraction
	dataAttrPatterns := []string{
		// HTML data attributes
		`data-([a-zA-Z][a-zA-Z0-9-]*)\s*=`,
		// Angular/Vue directives
		`(?:v-|ng-|@)([a-zA-Z][a-zA-Z0-9-]*)`,
		// React props
		`([a-zA-Z][a-zA-Z0-9]*)\s*=\s*\{`,
	}

	for _, pattern := range dataAttrPatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		allParameter = append(allParameter, matches...)
	}

	// Enhanced configuration object extraction
	configPatterns := []string{
		// Common config objects
		`(?:config|settings|options|params|data)\s*[:=]\s*\{[^}]*["']([a-zA-Z_][a-zA-Z0-9_]*)["']`,
		// Window/global variables
		`window\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=`,
		// Environment variables
		`(?:process\.env|ENV)\[?\s*["']([a-zA-Z_][a-zA-Z0-9_]*)["']`,
	}

	for _, pattern := range configPatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		allParameter = append(allParameter, matches...)
	}

	// Original paramfuzzer patterns (enhanced)
	funcPatterns := []string{
		// Enhanced function input patterns
		`(?:function\s+[\w\$]+|[\w\$]+\s*[=:]\s*function)\s*\(\s*([a-zA-Z_\$][\w\$]*(?:\s*,\s*[a-zA-Z_\$][\w\$]*)*)\s*\)`,
		// Method calls with parameters
		`\.[\w\$]+\s*\(\s*["']([a-zA-Z_][\w]*)["']`,
		// Object method definitions
		`([a-zA-Z_][\w]*)\s*\([^)]*\)\s*\{`,
		// Arrow functions
		`(?:const|let|var)\s+[\w\$]+\s*=\s*\(\s*([a-zA-Z_\$][\w\$]*(?:\s*,\s*[a-zA-Z_\$][\w\$]*)*)\s*\)\s*=>`,
	}

	for _, pattern := range funcPatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		for _, match := range matches {
			if strings.Contains(match, ",") {
				parts := strings.Split(match, ",")
				for _, part := range parts {
					part = strings.TrimSpace(part)
					if part != "" {
						allParameter = append(allParameter, part)
					}
				}
			} else {
				allParameter = append(allParameter, match)
			}
		}
	}

	// Enhanced path parameter extraction
	pathPatterns := []string{
		`\/\{([a-zA-Z_][\w]*)\}`,
		`:([a-zA-Z_][\w]*)(?:\/|\$|\?)`,
		`\$\{([a-zA-Z_][\w]*)\}`,
	}

	for _, pattern := range pathPatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		allParameter = append(allParameter, matches...)
	}

	// Enhanced query parameter extraction
	queryPatterns := []string{
		`[?&]([a-zA-Z_][\w]*)\s*=`,
		`[?&]([a-zA-Z_][\w]*)\s*:`,
		`params\[["']([a-zA-Z_][\w]*)["']`,
		`getParameter\s*\(\s*["']([a-zA-Z_][\w]*)["']`,
	}

	for _, pattern := range queryPatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		allParameter = append(allParameter, matches...)
	}

	// Enhanced API documentation patterns
	apiDocPatterns := []string{
		// OpenAPI/Swagger patterns
		`parameters\s*:\s*\[\s*\{\s*name\s*:\s*["']([a-zA-Z_][\w]*)["']`,
		// GraphQL schema
		`([a-zA-Z_][\w]*)\s*\([^)]*\)\s*:\s*\w+`,
		// REST documentation
		`\{([a-zA-Z_][\w]*)\}\s*-\s*[\w\s]+parameter`,
	}

	for _, pattern := range apiDocPatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		allParameter = append(allParameter, matches...)
	}

	// Enhanced cookie and storage patterns
	storagePatterns := []string{
		// Cookie operations
		`(?:document\.cookie|localStorage|sessionStorage).*["']([a-zA-Z_][\w]*)["']`,
		// Cookie manipulation libraries
		`Cookies\.(?:get|set)\s*\(\s*["']([a-zA-Z_][\w]*)["']`,
	}

	for _, pattern := range storagePatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		allParameter = append(allParameter, matches...)
	}

	// Original patterns from find.go
	if !strings.Contains(cnHeader, "javascript") {
		// HTML form inputs
		inputName := utils.MyRegex(`name\s*?=\s*?["|']([\w\-]+)["|']`, body, []int{1})
		allParameter = append(allParameter, inputName...)

		// HTML IDs
		htmlID := utils.MyRegex(`id\s*=\s*["|']([\w\-]+)["|']`, body, []int{1})
		allParameter = append(allParameter, htmlID...)

		// Enhanced HTML extraction
		formFields := utils.MyRegex(`<input[^>]+name=["']([^"']+)["']`, body, []int{1})
		allParameter = append(allParameter, formFields...)

		hiddenInputs := utils.MyRegex(`<input[^>]+type=["']hidden["'][^>]+name=["']([^"']+)["']`, body, []int{1})
		allParameter = append(allParameter, hiddenInputs...)
	}

	// XML attributes
	if strings.Contains(cnHeader, "xml") {
		xmlAtr := utils.MyRegex(`<([a-zA-Z0-9$_\.-]*?)>`, body, []int{1})
		allParameter = append(allParameter, xmlAtr...)
	}

	// Enhanced nested object extraction
	nestedObjectPatterns := []string{
		// JSON.stringify calls
		`JSON\.stringify\s*\(\s*\{[^}]*["']([a-zA-Z_][\w]*)["']`,
		// dataLayer pushes
		`dataLayer\.push\s*\(\s*\{[^}]*["']([a-zA-Z_][\w]*)["']`,
		// Complex object definitions
		`(?:var|let|const)\s+[\w\$]+\s*=\s*\{[^}]*["']([a-zA-Z_][\w]*)["']`,
	}

	for _, pattern := range nestedObjectPatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		allParameter = append(allParameter, matches...)
	}

	// Enhanced framework-specific patterns
	frameworkPatterns := []string{
		// React hooks
		`use(?:State|Effect|Context|Reducer)\s*\(\s*[^)]*["']([a-zA-Z_][\w]*)["']`,
		// Vue.js
		`(?:props|data|computed|methods)\s*:\s*\{[^}]*([a-zA-Z_][\w]*)\s*:`,
		// Angular
		`@(?:Input|Output|ViewChild)\s*\(\s*["']([a-zA-Z_][\w]*)["']`,
		// Next.js
		`getServerSideProps|getStaticProps.*["']([a-zA-Z_][\w]*)["']`,
	}

	for _, pattern := range frameworkPatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		allParameter = append(allParameter, matches...)
	}

	// Enhanced security-relevant patterns
	securityPatterns := []string{
		// CSRF tokens
		`(?:csrf|xsrf)[_-]?token["']?\s*[:=]\s*["']([a-zA-Z_][\w]*)["']`,
		// API keys
		`(?:api[_-]?key|access[_-]?token)["']?\s*[:=]\s*["']([a-zA-Z_][\w]*)["']`,
		// Authentication headers
		`Authorization["']?\s*[:=]\s*["'][^"']*["']`,
	}

	for _, pattern := range securityPatterns {
		matches := utils.MyRegex(pattern, body, []int{1})
		allParameter = append(allParameter, matches...)
	}

	// Clean and filter parameters using the enhanced cleaner
	cleanedParams := CleanParameterList(allParameter)

	// Only add non-empty cleaned parameters to result
	for _, v := range cleanedParams {
		if v != "" {
			result = append(result, v)
		}
	}

	return utils.Unique(result)
}

// extractJSONKeys extracts keys from a JSON string
func extractJSONKeys(jsonStr string) []string {
	var keys []string
	var obj map[string]interface{}

	if err := json.Unmarshal([]byte(jsonStr), &obj); err == nil {
		for key := range obj {
			// Only include keys that look like parameters
			if isValidParameterName(key) {
				keys = append(keys, key)
			}
		}
	}

	return keys
}

// isValidParameterName checks if a string looks like a valid parameter name
func isValidParameterName(name string) bool {
	// Must start with letter or underscore
	if len(name) == 0 {
		return false
	}

	first := name[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_') {
		return false
	}

	// Rest must be alphanumeric or underscore
	for i := 1; i < len(name); i++ {
		char := name[i]
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '_') {
			return false
		}
	}

	// Must be at least 2 characters long
	return len(name) >= 2
}

// GetSusParameters returns only the suspicious parameters from a slice of parameters
func GetSusParameters(params []string) map[string]string {
	susParams := make(map[string]string)
	for _, param := range params {
		if isSus, vulnType := IsSusParameter(param); isSus {
			susParams[param] = vulnType
		}
	}
	return susParams
}

// IsSusParameter checks if a parameter is suspicious (implementation from original)
func IsSusParameter(param string) (bool, string) {
	param = strings.ToLower(param)

	// SUS parameters from GAP
	var SUS_CMDI = []string{"execute", "dir", "daemon", "cli", "log", "cmd", "download", "ip", "upload"}
	var SUS_DEBUG = []string{"test", "reset", "config", "shell", "admin", "exec", "load", "cfg", "dbg", "edit", "root", "create", "access", "disable", "alter", "make", "grant", "adm", "toggle", "execute", "clone", "delete", "enable", "rename", "debug", "modify"}
	var SUS_FILEINC = []string{"root", "directory", "path", "style", "folder", "default-language", "url", "platform", "textdomain", "document", "template", "pg", "php_path", "doc", "type", "lang", "token", "name", "pdf", "file", "etc", "api", "app", "resource-type"}
	var SUS_IDOR = []string{"count", "key", "user", "id", "extended_data", "uid2", "group", "team_id", "data-id", "no", "username", "email", "account", "doc", "uuid", "profile", "number", "user_id", "edit", "report", "order"}
	var SUS_OPENREDIRECT = []string{"u", "redirect_uri", "failed", "r", "referer", "return_url", "redirect_url", "prejoin_data", "continue", "redir", "return_to", "origin", "redirect_to", "next"}
	var SUS_SQLI = []string{"process", "string", "id", "referer", "password", "pwd", "field", "view", "sleep", "column", "log", "token", "sel", "select", "sort", "from", "search", "update", "pub_group_id", "row", "results", "role", "table", "multi_layer_map_list", "order", "filter", "params", "user", "fetch", "limit", "keyword", "email", "query", "c", "name", "where", "number", "phone_number", "delete", "report"}
	var SUS_SSRF = []string{"dest", "redirect", "uri", "path", "continue", "url", "window", "next", "data", "reference", "site", "html", "val", "validate", "domain", "callback", "return", "page", "feed", "host", "port", "to", "out", "view", "dir", "show", "navigation", "open"}

	// Check each category
	for _, sus := range SUS_CMDI {
		if strings.Contains(param, sus) {
			return true, "CMDI"
		}
	}

	for _, sus := range SUS_DEBUG {
		if strings.Contains(param, sus) {
			return true, "DEBUG"
		}
	}

	for _, sus := range SUS_FILEINC {
		if strings.Contains(param, sus) {
			return true, "FILEINC"
		}
	}

	for _, sus := range SUS_IDOR {
		if strings.Contains(param, sus) {
			return true, "IDOR"
		}
	}

	for _, sus := range SUS_OPENREDIRECT {
		if strings.Contains(param, sus) {
			return true, "OPENREDIRECT"
		}
	}

	for _, sus := range SUS_SQLI {
		if strings.Contains(param, sus) {
			return true, "SQLI"
		}
	}

	for _, sus := range SUS_SSRF {
		if strings.Contains(param, sus) {
			return true, "SSRF"
		}
	}

	return false, ""
}
