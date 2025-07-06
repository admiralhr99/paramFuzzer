package parameters

import (
	"github.com/admiralhr99/paramFuzzer/funcs/utils"
	"net/url"
	"strings"
)

func Find(link string, body string, cnHeader string) []string {
	var allParameter []string

	// Get parameter from url
	linkParameter := QueryStringKey(link)
	allParameter = append(allParameter, linkParameter...)

	// Enhanced Variable Name extraction with improved spacing handling
	variableNamesRegex := utils.MyRegex(`(let|const|var)\s+([\w\,\s]+)\s*?(\n|\r|;|=)`, body, []int{2})
	var variableNames []string
	for _, v := range variableNamesRegex {
		for _, j := range strings.Split(v, ",") {
			variableNames = append(variableNames, strings.Replace(j, " ", "", -1))
		}
	}
	allParameter = append(allParameter, variableNames...)

	// NEW: Function name extraction from const/let/var declarations
	functionDeclarationNames := utils.MyRegex(`(let|const|var)\s+([\w\-]+)\s*=\s*(?:\([^)]*\)\s*=>|\(.*?\)\s*=>\s*\{|function)`, body, []int{2})
	allParameter = append(allParameter, functionDeclarationNames...)

	// NEW: Arrow function names with parameters
	arrowFunctionNames := utils.MyRegex(`(let|const|var)\s+([\w\-]+)\s*=\s*\([^)]*\)\s*=>\s*`, body, []int{2})
	allParameter = append(allParameter, arrowFunctionNames...)

	// NEW: Variable assignments with getElementById, querySelector, etc.
	domVariableAssignments := utils.MyRegex(`(let|const|var)\s+([\w\-]+)\s*=\s*document\.(?:getElementById|querySelector|querySelectorAll|getElementsByClassName)`, body, []int{2})
	allParameter = append(allParameter, domVariableAssignments...)

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

	// NEW: Enhanced unquoted object properties (common in JS objects)
	unquotedObjectKeys := utils.MyRegex(`^\s*([\w\-]+)\s*:\s*`, body, []int{1})
	allParameter = append(allParameter, unquotedObjectKeys...)

	// NEW: Object properties in multi-line objects
	objectPropertiesMultiline := utils.MyRegex(`\n\s*([\w\-]+)\s*:\s*[^,\n}]+[,}]`, body, []int{1})
	allParameter = append(allParameter, objectPropertiesMultiline...)

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
		// NEW: Enhanced HTML id attribute extraction
		htmlIdAttributes := utils.MyRegex(`id\s*=\s*["|']([\w\-]+)["|']`, body, []int{1})
		allParameter = append(allParameter, htmlIdAttributes...)

		// Enhanced Name HTML attribute
		inputName := utils.MyRegex(`name\s*?=\s*?["|']([\w\-]+)["|']`, body, []int{1})
		allParameter = append(allParameter, inputName...)

		// Enhanced Class HTML attribute
		inputClass := utils.MyRegex(`class\s*=\s*["|']([^"']*?)["|']`, body, []int{1})
		for _, classes := range inputClass {
			for _, class := range strings.Split(classes, " ") {
				cleaned := strings.TrimSpace(class)
				if cleaned != "" && len(cleaned) > 2 {
					allParameter = append(allParameter, cleaned)
				}
			}
		}

		// Data attributes
		dataAttributes := utils.MyRegex(`data-([\w\-]+)\s*=`, body, []int{1})
		allParameter = append(allParameter, dataAttributes...)

		// Aria attributes
		ariaAttributes := utils.MyRegex(`aria-([\w\-]+)\s*=`, body, []int{1})
		allParameter = append(allParameter, ariaAttributes...)

		// For attributes in labels
		forAttributes := utils.MyRegex(`for\s*=\s*["|']([\w\-]+)["|']`, body, []int{1})
		allParameter = append(allParameter, forAttributes...)

		// Action attributes in forms
		actionAttributes := utils.MyRegex(`action\s*=\s*["|'][^"']*?\?([\w\-]+=[\w\-]*&?)*[^"']*?["|']`, body, []int{1})
		allParameter = append(allParameter, actionAttributes...)

		// Href attributes with parameters
		hrefParams := utils.MyRegex(`href\s*=\s*["|'][^"']*?\?([\w\-]+=[\w\-]*&?)*[^"']*?["|']`, body, []int{1})
		allParameter = append(allParameter, hrefParams...)

		// Meta tag content extraction
		metaContent := utils.MyRegex(`<meta[^>]*content\s*=\s*["|']([^"']+)["|']`, body, []int{1})
		allParameter = append(allParameter, metaContent...)

		// Meta tag property names
		metaProps := utils.MyRegex(`<meta[^>]*(?:name|property)=["']([^"']+)["']`, body, []int{1})
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
	authParams := utils.MyRegex(`(?:authorization|auth|token)[^}]*?([\w\-]+)\s*:`, body, []int{1})
	allParameter = append(allParameter, authParams...)

	// NEW: Dataset attribute extraction (data-* attributes)
	datasetAttributes := utils.MyRegex(`dataset\.([\w\-]+)`, body, []int{1})
	allParameter = append(allParameter, datasetAttributes...)

	// NEW: CSS selector extraction (for dynamic element selection)
	cssSelectors := utils.MyRegex(`["|']#([\w\-]+)["|']`, body, []int{1})
	allParameter = append(allParameter, cssSelectors...)

	// NEW: CSS class selectors
	cssClassSelectors := utils.MyRegex(`["|']\.([\w\-]+)["|']`, body, []int{1})
	allParameter = append(allParameter, cssClassSelectors...)

	// NEW: Enhanced for loop variable extraction
	forLoopVars := utils.MyRegex(`for\s*\(\s*(?:let|const|var)?\s*([\w\-]+)`, body, []int{1})
	allParameter = append(allParameter, forLoopVars...)

	// NEW: forEach parameter extraction
	forEachParams := utils.MyRegex(`forEach\s*\(\s*(?:\(?\s*)?([\w\-]+)`, body, []int{1})
	allParameter = append(allParameter, forEachParams...)

	// NEW: Map function parameter extraction
	mapParams := utils.MyRegex(`\.map\s*\(\s*(?:\(?\s*)?([\w\-]+)`, body, []int{1})
	allParameter = append(allParameter, mapParams...)

	// NEW: Filter function parameter extraction
	filterParams := utils.MyRegex(`\.filter\s*\(\s*(?:\(?\s*)?([\w\-]+)`, body, []int{1})
	allParameter = append(allParameter, filterParams...)

	// ONLY CHANGED PART: Use new cleaner instead of old cleanup
	// Basic cleanup first - remove empty and trim spaces
	var rawParams []string
	for _, v := range allParameter {
		cleaned := strings.TrimSpace(v)
		if cleaned != "" && len(cleaned) > 0 {
			rawParams = append(rawParams, cleaned)
		}
	}

	// Remove basic duplicates
	rawParams = utils.Unique(rawParams)

	// Apply the new enhanced cleaner with strict ASCII rules and = splitting
	result := CleanParameterList(rawParams)

	return result
}

func QueryStringKey(link string) []string {
	var result []string
	linkParsed, err := url.Parse(link)
	if err != nil {
		return result
	}

	for k := range linkParsed.Query() {
		result = append(result, k)
	}

	return result
}
