// parameters/find.go - Updated with parameter cleaning

package parameters

import (
	"github.com/admiralhr99/paramFuzzer/funcs/utils"
	"net/url"
	"strings"
)

// SUS parameters from GAP
var SUS_CMDI = []string{"execute", "dir", "daemon", "cli", "log", "cmd", "download", "ip", "upload"}
var SUS_DEBUG = []string{"test", "reset", "config", "shell", "admin", "exec", "load", "cfg", "dbg", "edit", "root", "create", "access", "disable", "alter", "make", "grant", "adm", "toggle", "execute", "clone", "delete", "enable", "rename", "debug", "modify"}
var SUS_FILEINC = []string{"root", "directory", "path", "style", "folder", "default-language", "url", "platform", "textdomain", "document", "template", "pg", "php_path", "doc", "type", "lang", "token", "name", "pdf", "file", "etc", "api", "app", "resource-type"}
var SUS_IDOR = []string{"count", "key", "user", "id", "extended_data", "uid2", "group", "team_id", "data-id", "no", "username", "email", "account", "doc", "uuid", "profile", "number", "user_id", "edit", "report", "order"}
var SUS_OPENREDIRECT = []string{"u", "redirect_uri", "failed", "r", "referer", "return_url", "redirect_url", "prejoin_data", "continue", "redir", "return_to", "origin", "redirect_to", "next"}
var SUS_SQLI = []string{"process", "string", "id", "referer", "password", "pwd", "field", "view", "sleep", "column", "log", "token", "sel", "select", "sort", "from", "search", "update", "pub_group_id", "row", "results", "role", "table", "multi_layer_map_list", "order", "filter", "params", "user", "fetch", "limit", "keyword", "email", "query", "c", "name", "where", "number", "phone_number", "delete", "report"}
var SUS_SSRF = []string{"sector_identifier_uri", "request_uris", "logo_uri", "jwks_uri", "start", "path", "domain", "source", "url", "site", "view", "template", "page", "show", "val", "dest", "metadata", "out", "feed", "navigation", "image_host", "uri", "next", "continue", "host", "window", "dir", "reference", "filename", "html", "to", "return", "open", "port", "stop", "validate", "resturl", "callback", "name", "data", "ip", "redirect"}
var SUS_SSTI = []string{"preview", "activity", "id", "name", "content", "view", "template", "redirect"}
var SUS_XSS = []string{"path", "admin", "class", "atb", "redirect_uri", "other", "utm_source", "currency", "dir", "title", "endpoint", "return_url", "users", "cookie", "state", "callback", "militarybranch", "e", "referer", "password", "author", "body", "status", "utm_campaign", "value", "text", "search", "flaw", "vote", "pathname", "params", "user", "t", "utm_medium", "q", "email", "what", "file", "data-original", "description", "subject", "action", "u", "nickname", "color", "language_id", "auth", "samlresponse", "return", "readyfunction", "where", "tags", "cvo_sid1", "target", "format", "back", "term", "r", "id", "url", "view", "username", "sequel", "type", "city", "src", "p", "label", "ctx", "style", "html", "ad_type", "s", "issues", "query", "c", "shop", "redirect"}
var SUS_MASSASSIGNMENT = []string{"user", "profile", "role", "settings", "data", "attributes", "post", "comment", "order", "product", "form_fields", "request"}

// Maps to store sus parameters for quick lookup
var susParamMap map[string]string

func init() {
	// Initialize the map for quick sus param lookups
	susParamMap = make(map[string]string)

	for _, param := range SUS_CMDI {
		susParamMap[param] = "CMDI"
	}
	for _, param := range SUS_DEBUG {
		susParamMap[param] = "DEBUG"
	}
	for _, param := range SUS_FILEINC {
		susParamMap[param] = "FILEINC"
	}
	for _, param := range SUS_IDOR {
		susParamMap[param] = "IDOR"
	}
	for _, param := range SUS_OPENREDIRECT {
		susParamMap[param] = "OPENREDIRECT"
	}
	for _, param := range SUS_SQLI {
		susParamMap[param] = "SQLI"
	}
	for _, param := range SUS_SSRF {
		susParamMap[param] = "SSRF"
	}
	for _, param := range SUS_SSTI {
		susParamMap[param] = "SSTI"
	}
	for _, param := range SUS_XSS {
		susParamMap[param] = "XSS"
	}
	for _, param := range SUS_MASSASSIGNMENT {
		susParamMap[param] = "MASSASSIGN"
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

// IsSusParameter determines if a parameter is suspicious and returns its type
func IsSusParameter(param string) (bool, string) {
	paramLower := strings.ToLower(param)
	if vulnType, exists := susParamMap[paramLower]; exists {
		return true, vulnType
	}
	return false, ""
}

func Find(link string, body string, cnHeader string) []string {
	var allParameter []string
	var result []string

	// Get parameter from url
	linkParameter := QueryStringKey(link)
	allParameter = append(allParameter, linkParameter...)

	// Variable Name
	variableNamesRegex := utils.MyRegex(`(let|const|var)\s([\w\,\s]+)\s*?(\n|\r|;|=)`, body, []int{2})
	var variableNames []string
	for _, v := range variableNamesRegex {
		for _, j := range strings.Split(v, ",") {
			variableNames = append(variableNames, strings.Replace(j, " ", "", -1))
		}
	}
	allParameter = append(allParameter, variableNames...)

	// Json and Object keys
	jsonObjectKey := utils.MyRegex(`["|']([\w\-]+)["|']\s*?:`, body, []int{1})
	allParameter = append(allParameter, jsonObjectKey...)

	// String format variable
	stringFormat := utils.MyRegex(`\${(\s*[\w\-]+)\s*}`, body, []int{1})
	allParameter = append(allParameter, stringFormat...)

	// Function input
	funcInput := utils.MyRegex(`.*\(\s*["|']?([\w\-]+)["|']?\s*(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?(\,\s*["|']?([\w\-]+)["|']?\s*)?\)`,
		body, []int{1, 3, 5, 7, 9, 11, 13, 15, 17, 19})
	allParameter = append(allParameter, funcInput...)

	// Path Input
	pathInput := utils.MyRegex(`\/\{(.*)\}`, body, []int{1})
	allParameter = append(allParameter, pathInput...)

	// Query string key in source
	queryString := utils.MyRegex(`(\?([\w\-]+)=)|(\&([\w\-]+)=)`, body, []int{2, 4})
	allParameter = append(allParameter, queryString...)

	// Added from GAP.py - Query parameters in JavaScript
	jsParamRegex := utils.MyRegex(`[?&][a-zA-Z0-9_\-]{3,}=`, body, []int{0})
	for _, p := range jsParamRegex {
		param := strings.TrimPrefix(strings.TrimPrefix(p, "?"), "&")
		param = strings.TrimSuffix(param, "=")
		if param != "" {
			allParameter = append(allParameter, param)
		}
	}

	if cnHeader != "application/javascript" {
		// Name HTML attribute
		inputName := utils.MyRegex(`name\s*?=\s*?["|']([\w\-]+)["|']`, body, []int{1})
		allParameter = append(allParameter, inputName...)

		// ID HTML attribute
		htmlID := utils.MyRegex(`id\s*=\s*["|']([\w\-]+)["|']`, body, []int{1})
		allParameter = append(allParameter, htmlID...)

		// Enhanced HTML extraction from GAP
		// Form fields
		formFields := utils.MyRegex(`<input[^>]+name=["']([^"']+)["']`, body, []int{1})
		allParameter = append(allParameter, formFields...)

		// Hidden inputs
		hiddenInputs := utils.MyRegex(`<input[^>]+type=["']hidden["'][^>]+name=["']([^"']+)["']`, body, []int{1})
		allParameter = append(allParameter, hiddenInputs...)
	}

	// XML attributes
	if strings.Contains(cnHeader, "xml") {
		xmlAtr := utils.MyRegex(`<([a-zA-Z0-9$_\.-]*?)>`, body, []int{1})
		allParameter = append(allParameter, xmlAtr...)
	}

	// Added from GAP.py - Nested JavaScript objects
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
					break
				}
			}
		}
	}

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
