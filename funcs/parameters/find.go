// parameters/find.go - Enhanced with comprehensive parameter extraction

package parameters

import (
	"github.com/admiralhr99/paramFuzzer/funcs/utils"
	"net/url"
	"strings"
)

func Find(link string, body string, cnHeader string) []string {
	var allParameter []string
	var result []string

	// Get parameter from url
	linkParameter := QueryStringKey(link)
	allParameter = append(allParameter, linkParameter...)

	// Enhanced Variable Name extraction
	variableNamesRegex := utils.MyRegex(`(let|const|var)\s([\w\,\s]+)\s*?(\n|\r|;|=)`, body, []int{2})
	var variableNames []string
	for _, v := range variableNamesRegex {
		for _, j := range strings.Split(v, ",") {
			variableNames = append(variableNames, strings.Replace(j, " ", "", -1))
		}
	}
	allParameter = append(allParameter, variableNames...)

	// Enhanced ES6+ variable declarations
	es6Variables := utils.MyRegex(`(let|const)\s*\{\s*([\w\s,]+)\s*\}\s*=`, body, []int{2})
	for _, v := range es6Variables {
		for _, j := range strings.Split(v, ",") {
			cleaned := strings.TrimSpace(j)
			if cleaned != "" {
				variableNames = append(variableNames, cleaned)
			}
		}
	}
	allParameter = append(allParameter, variableNames...)

	// Array destructuring
	arrayDestructuring := utils.MyRegex(`(let|const|var)\s*\[\s*([\w\s,]+)\s*\]\s*=`, body, []int{2})
	for _, v := range arrayDestructuring {
		for _, j := range strings.Split(v, ",") {
			cleaned := strings.TrimSpace(j)
			if cleaned != "" {
				allParameter = append(allParameter, cleaned)
			}
		}
	}

	// Enhanced Json and Object keys
	jsonObjectKey := utils.MyRegex(`["|']([\w\-]+)["|']\s*?:`, body, []int{1})
	allParameter = append(allParameter, jsonObjectKey...)

	// Object keys without quotes (ES6 shorthand)
	objectKeysNoQuotes := utils.MyRegex(`\{\s*([\w\-]+)\s*[,}]`, body, []int{1})
	allParameter = append(allParameter, objectKeysNoQuotes...)

	// Object method definitions
	objectMethods := utils.MyRegex(`([\w\-]+)\s*\([^)]*\)\s*\{`, body, []int{1})
	allParameter = append(allParameter, objectMethods...)

	// Enhanced String format variable
	stringFormat := utils.MyRegex(`\${(\s*[\w\-]+)\s*}`, body, []int{1})
	allParameter = append(allParameter, stringFormat...)

	// Template literal variables
	templateLiterals := utils.MyRegex(`\$\{[^}]*?([\w\-]+)[^}]*?\}`, body, []int{1})
	allParameter = append(allParameter, templateLiterals...)

	// Enhanced Function input (keeping original complexity)
	funcInput := utils.MyRegex(`.*\(\s*["|']?([\w\-]+)["|']?\s*(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?\)`,
		body, []int{1, 3, 5, 7, 9, 11, 13, 15, 17, 19})
	allParameter = append(allParameter, funcInput...)

	// Arrow function parameters
	arrowFunctions := utils.MyRegex(`([\w\-]+)\s*=>\s*`, body, []int{1})
	allParameter = append(allParameter, arrowFunctions...)

	// Multi-parameter arrow functions
	arrowFunctionMulti := utils.MyRegex(`\(\s*([\w\-,\s]+)\s*\)\s*=>\s*`, body, []int{1})
	for _, v := range arrowFunctionMulti {
		for _, j := range strings.Split(v, ",") {
			cleaned := strings.TrimSpace(j)
			if cleaned != "" {
				allParameter = append(allParameter, cleaned)
			}
		}
	}

	// Function declarations with parameters
	functionDeclarations := utils.MyRegex(`function\s+[\w\-]+\s*\(\s*([\w\-,\s]*)\s*\)`, body, []int{1})
	for _, v := range functionDeclarations {
		for _, j := range strings.Split(v, ",") {
			cleaned := strings.TrimSpace(j)
			if cleaned != "" {
				allParameter = append(allParameter, cleaned)
			}
		}
	}

	// Enhanced Path Input
	pathInput := utils.MyRegex(`\/\{(.*)\}`, body, []int{1})
	allParameter = append(allParameter, pathInput...)

	// REST API path parameters
	restApiParams := utils.MyRegex(`\/:([\w\-]+)`, body, []int{1})
	allParameter = append(allParameter, restApiParams...)

	// Express.js style parameters
	expressParams := utils.MyRegex(`req\.params\.([\w\-]+)`, body, []int{1})
	allParameter = append(allParameter, expressParams...)

	// Enhanced Query string key in source
	queryString := utils.MyRegex(`(\?([\w\-]+)=)|(\&([\w\-]+)=)`, body, []int{2, 4})
	allParameter = append(allParameter, queryString...)

	// URL search params
	urlSearchParams := utils.MyRegex(`URLSearchParams[^}]*?get\s*\(\s*["|']([\w\-]+)["|']`, body, []int{1})
	allParameter = append(allParameter, urlSearchParams...)

	// Query selector parameters
	querySelector := utils.MyRegex(`querySelector\s*\(\s*["|'][^"']*?([\w\-]+)[^"']*?["|']`, body, []int{1})
	allParameter = append(allParameter, querySelector...)

	// Added from GAP.py - Enhanced Query parameters in JavaScript
	jsParamRegex := utils.MyRegex(`[?&][a-zA-Z0-9_\-]{3,}=`, body, []int{0})
	for _, p := range jsParamRegex {
		param := strings.TrimPrefix(strings.TrimPrefix(p, "?"), "&")
		param = strings.TrimSuffix(param, "=")
		if param != "" {
			allParameter = append(allParameter, param)
		}
	}

	// URL parameter extraction from strings
	urlParamsInStrings := utils.MyRegex(`["|']/[^"']*\?([\w\-]+=[\w\-]*&?)([^"']*)["|']`, body, []int{1})
	for _, paramString := range urlParamsInStrings {
		params := strings.Split(paramString, "&")
		for _, param := range params {
			if strings.Contains(param, "=") {
				key := strings.Split(param, "=")[0]
				if key != "" {
					allParameter = append(allParameter, key)
				}
			}
		}
	}

	// Enhanced request/response parameter extraction
	requestParams := utils.MyRegex(`req(?:uest)?\.(?:query|body|params)\.([\w\-]+)`, body, []int{1})
	allParameter = append(allParameter, requestParams...)

	// Form data extraction
	formDataParams := utils.MyRegex(`FormData[^}]*?append\s*\(\s*["|']([\w\-]+)["|']`, body, []int{1})
	allParameter = append(allParameter, formDataParams...)

	// AJAX data parameters
	ajaxParams := utils.MyRegex(`data\s*:\s*\{[^}]*?([\w\-]+)\s*:`, body, []int{1})
	allParameter = append(allParameter, ajaxParams...)

	// Fetch API parameters
	fetchParams := utils.MyRegex(`fetch\s*\([^)]*?\{[^}]*?([\w\-]+)\s*:`, body, []int{1})
	allParameter = append(allParameter, fetchParams...)

	// localStorage/sessionStorage keys
	storageKeys := utils.MyRegex(`(?:localStorage|sessionStorage)\.(?:getItem|setItem)\s*\(\s*["|']([\w\-]+)["|']`, body, []int{1})
	allParameter = append(allParameter, storageKeys...)

	// Cookie parameter extraction
	cookieParams := utils.MyRegex(`document\.cookie[^;]*?([\w\-]+)\s*=`, body, []int{1})
	allParameter = append(allParameter, cookieParams...)

	// Event listener parameters
	eventParams := utils.MyRegex(`addEventListener\s*\(\s*["|']([\w\-]+)["|']`, body, []int{1})
	allParameter = append(allParameter, eventParams...)

	// React/Vue component props
	componentProps := utils.MyRegex(`props\.([\w\-]+)`, body, []int{1})
	allParameter = append(allParameter, componentProps...)

	// Vue.js data properties
	vueDataProps := utils.MyRegex(`this\.([\w\-]+)`, body, []int{1})
	allParameter = append(allParameter, vueDataProps...)

	// Angular directive parameters
	angularParams := utils.MyRegex(`\[\(?([\w\-]+)\)?\]`, body, []int{1})
	allParameter = append(allParameter, angularParams...)

	if cnHeader != "application/javascript" {
		// Enhanced Name HTML attribute
		inputName := utils.MyRegex(`name\s*?=\s*?["|']([\w\-]+)["|']`, body, []int{1})
		allParameter = append(allParameter, inputName...)

		// Enhanced ID HTML attribute
		htmlID := utils.MyRegex(`id\s*=\s*["|']([\w\-]+)["|']`, body, []int{1})
		allParameter = append(allParameter, htmlID...)

		// Enhanced HTML extraction from GAP
		// Form fields
		formFields := utils.MyRegex(`<input[^>]+name=["']([^"']+)["']`, body, []int{1})
		allParameter = append(allParameter, formFields...)

		// Hidden inputs
		hiddenInputs := utils.MyRegex(`<input[^>]+type=["']hidden["'][^>]+name=["']([^"']+)["']`, body, []int{1})
		allParameter = append(allParameter, hiddenInputs...)

		// Select options with values
		selectOptions := utils.MyRegex(`<option[^>]+value=["']([^"']+)["']`, body, []int{1})
		allParameter = append(allParameter, selectOptions...)

		// Data attributes
		dataAttributes := utils.MyRegex(`data-([\w\-]+)=`, body, []int{1})
		allParameter = append(allParameter, dataAttributes...)

		// Class names that might be parameters
		classParams := utils.MyRegex(`class=["'][^"']*?([\w\-]{3,})[^"']*?["']`, body, []int{1})
		allParameter = append(allParameter, classParams...)

		// Form action parameters
		formActions := utils.MyRegex(`action=["'][^"']*\?([\w\-]+=[\w\-]*&?)[^"']*["']`, body, []int{1})
		for _, paramString := range formActions {
			params := strings.Split(paramString, "&")
			for _, param := range params {
				if strings.Contains(param, "=") {
					key := strings.Split(param, "=")[0]
					if key != "" {
						allParameter = append(allParameter, key)
					}
				}
			}
		}

		// Link href parameters
		linkParams := utils.MyRegex(`href=["'][^"']*\?([\w\-]+=[\w\-]*&?)[^"']*["']`, body, []int{1})
		for _, paramString := range linkParams {
			params := strings.Split(paramString, "&")
			for _, param := range params {
				if strings.Contains(param, "=") {
					key := strings.Split(param, "=")[0]
					if key != "" {
						allParameter = append(allParameter, key)
					}
				}
			}
		}

		// Meta property names
		metaProps := utils.MyRegex(`<meta[^>]+(?:name|property)=["']([^"']+)["']`, body, []int{1})
		allParameter = append(allParameter, metaProps...)
	}

	// XML attributes
	if strings.Contains(cnHeader, "xml") {
		xmlAtr := utils.MyRegex(`<([a-zA-Z0-9$_\.-]*?)>`, body, []int{1})
		allParameter = append(allParameter, xmlAtr...)

		// XML attribute names
		xmlAttrs := utils.MyRegex(`<[^>]+\s([\w\-]+)=`, body, []int{1})
		allParameter = append(allParameter, xmlAttrs...)
	}

	// Enhanced GAP.py - Nested JavaScript objects (keeping original complexity)
	nestedObjects := utils.MyRegex(`(JSON\.stringify\(|dataLayer\.push\(|(var|let|const)\s+[\$A-Za-z0-9-_\[\]]+\s*=)\s*\{`, body, []int{0})
	for _, match := range nestedObjects {
		// Find the start of the object
		start := strings.Index(body, match) + len(match)
		// Find balanced closing brace
		nested := 0
		for i := start; i < len(body); i++ {
			if body[i] == '{' {
				nested++
			} else if body[i] == '}' {
				nested--
				if nested < 0 {
					// Extract object keys
					objectContent := body[start:i]
					keyRegex := utils.MyRegex(`["']([A-Za-z0-9_\-\.]+)["']\s*:`, objectContent, []int{1})
					allParameter = append(allParameter, keyRegex...)

					// Also extract unquoted keys
					unquotedKeys := utils.MyRegex(`\s([A-Za-z_][A-Za-z0-9_\-]*)\s*:`, objectContent, []int{1})
					allParameter = append(allParameter, unquotedKeys...)
					break
				}
			}
		}
	}

	// GraphQL query parameters
	graphqlParams := utils.MyRegex(`query[^{]*\{[^}]*?([\w\-]+)\s*\(`, body, []int{1})
	allParameter = append(allParameter, graphqlParams...)

	// GraphQL variables
	graphqlVars := utils.MyRegex(`variables\s*:\s*\{[^}]*?([\w\-]+)\s*:`, body, []int{1})
	allParameter = append(allParameter, graphqlVars...)

	// API endpoint parameters from comments
	commentParams := utils.MyRegex(`//.*?@param\s+([\w\-]+)`, body, []int{1})
	allParameter = append(allParameter, commentParams...)

	// JSDoc parameters
	jsdocParams := utils.MyRegex(`\*\s*@param\s+\{[^}]*\}\s+([\w\-]+)`, body, []int{1})
	allParameter = append(allParameter, jsdocParams...)

	// Environment variables
	envVars := utils.MyRegex(`process\.env\.([\w\-]+)`, body, []int{1})
	allParameter = append(allParameter, envVars...)

	// Configuration object keys
	configKeys := utils.MyRegex(`config\s*:\s*\{[^}]*?([\w\-]+)\s*:`, body, []int{1})
	allParameter = append(allParameter, configKeys...)

	// Database query parameters
	dbParams := utils.MyRegex(`(?:WHERE|SELECT|INSERT|UPDATE)[^;]*?([\w\-]+)\s*=`, body, []int{1})
	allParameter = append(allParameter, dbParams...)

	// Webhook parameters
	webhookParams := utils.MyRegex(`webhook[^}]*?([\w\-]+)\s*:`, body, []int{1})
	allParameter = append(allParameter, webhookParams...)

	// Header parameters
	headerParams := utils.MyRegex(`headers\s*:\s*\{[^}]*?([\w\-]+)\s*:`, body, []int{1})
	allParameter = append(allParameter, headerParams...)

	// Authorization parameters
	authParams := utils.MyRegex(`(?:authorization|auth|token)[^}]*?([\w\-]+)\s*[=:]`, body, []int{1})
	allParameter = append(allParameter, authParams...)

	// Clean and filter parameters
	cleanedParams := CleanParameterList(allParameter)

	// Only add non-empty cleaned parameters to result
	for _, v := range cleanedParams {
		if v != "" {
			result = append(result, v)
		}
	}

	return result
}

// JavaScript dangerous sinks only
var JS_CODE_EXECUTION = []string{"eval", "function", "settimeout", "setinterval", "execscript", "compile", "execute", "run", "execcommand", "createfunction"}
var JS_DOM_MANIPULATION = []string{"innerhtml", "outerhtml", "insertadjacenthtml", "document.write", "document.writeln", "createelement", "appendchild", "insertbefore", "replaceChild"}
var JS_SCRIPT_INJECTION = []string{"script", "javascript", "src", "href", "action", "formaction", "background", "lowsrc", "data", "value", "content"}
var JS_DYNAMIC_IMPORT = []string{"import", "require", "load", "include", "module", "plugin", "component", "loadmodule", "importscripts"}
var JS_TEMPLATE_ENGINE = []string{"template", "render", "compile", "mustache", "handlebars", "ejs", "pug", "vue", "angular", "react", "jsx"}
var JS_EVENT_HANDLERS = []string{"onclick", "onload", "onerror", "onmouseover", "onfocus", "onblur", "onchange", "onsubmit", "onmouseout", "onkeydown", "onkeyup"}
var JS_NAVIGATION = []string{"location", "redirect", "href", "assign", "replace", "reload", "open", "close", "navigate", "pushstate", "replacestate"}
var JS_ATTRIBUTE_SINKS = []string{"style", "class", "id", "name", "title", "alt", "placeholder", "pattern", "formnovalidate"}
var JS_URL_SINKS = []string{"url", "uri", "link", "path", "route", "endpoint", "api", "callback", "jsonp", "websocket"}
var JS_JSON_SINKS = []string{"json", "parse", "stringify", "data", "response", "payload", "config", "options", "params"}

// Maps to store JavaScript dangerous sinks only
var jsDangerousSinkMap map[string]string

func init() {
	// Initialize the map for JavaScript dangerous sinks only
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

func QueryStringKey(link string) []string {
	u, e := url.Parse(link)
	utils.CheckError(e)
	var keys []string
	for _, v := range strings.Split(u.RawQuery, "&") {
		if v != "" {
			paramParts := strings.SplitN(v, "=", 2)
			if len(paramParts) > 0 && paramParts[0] != "" {
				keys = append(keys, paramParts[0])
			}
		}
	}
	return keys
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

// GetSusParameters returns only JavaScript dangerous sink parameters
func GetSusParameters(params []string) map[string]string {
	susParams := make(map[string]string)
	for _, param := range params {
		if isSus, vulnType := IsSusParameter(param); isSus {
			susParams[param] = vulnType
		}
	}
	return susParams
}
