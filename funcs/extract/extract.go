package extract

import (
	"encoding/json"
	"fmt"
	"github.com/admiralhr99/paramFuzzer/funcs/opt"
	"github.com/admiralhr99/paramFuzzer/funcs/utils"
	"github.com/admiralhr99/paramFuzzer/funcs/validate"
	"github.com/projectdiscovery/gologger"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Result structure for storing parameters
type Result struct {
	Parameter  string   `json:"parameter"`
	Source     string   `json:"source"`
	URL        string   `json:"url"`
	Confidence string   `json:"confidence"`
	VulnTypes  []string `json:"vuln_types,omitempty"`
}

// AllResults stores all unique parameters found
var AllResults = struct {
	sync.Mutex
	Results []Result
}{Results: []Result{}}

// ParamSet stores unique parameter names
var ParamSet = struct {
	sync.Mutex
	params map[string]bool
}{params: make(map[string]bool)}

// Regular expressions for parameter extraction
var (
	// Query string parameters
	regexQueryParams = regexp.MustCompile(`(?:^|\?|&)([^=&]+)=`)

	// HTML form input fields
	regexFormFields = regexp.MustCompile(`<input.*?name=["']([^"']+)["']`)
	regexFormAction = regexp.MustCompile(`<form.*?action=["']([^"']+)["']`)

	// URL path parameters
	regexPathParams   = regexp.MustCompile(`\/\{([a-zA-Z0-9_-]+)\}`)
	regexPathSegments = regexp.MustCompile(`\/([a-zA-Z][a-zA-Z0-9_-]+)`)

	// JavaScript parameters
	regexJsParams     = regexp.MustCompile(`[?&;]([^=&;]+)=`)
	regexJsVars       = regexp.MustCompile(`(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)`)
	regexJsFuncParams = regexp.MustCompile(`function\s+[a-zA-Z_$][a-zA-Z0-9_$]*\s*\(([^)]*)\)`)

	// JSON parameters
	regexJsonKeys = regexp.MustCompile(`"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:`)

	// Comments that might contain parameters
	regexHtmlComments = regexp.MustCompile(`<!--(.*?)-->`)
	regexJsComments   = regexp.MustCompile(`(?://.*?$)|(?:/\*.*?\*/)`)
)

// Start processes URLs from the input channel
func Start(channel chan string, myOptions *opt.Options, wg *sync.WaitGroup) {
	defer wg.Done()
	for input := range channel {
		results := Process(input, myOptions)

		for _, result := range results {
			if len(result.Parameter) <= myOptions.MaxLength && len(result.Parameter) >= myOptions.MinLength {
				// Check if we should show only suspicious parameters
				if myOptions.ReportSuspiciousOnly {
					isSuspicious, vulnTypes := utils.IsSuspiciousParameter(result.Parameter)
					if isSuspicious {
						result.VulnTypes = vulnTypes
						writeResult(result, myOptions)
					}
				} else {
					writeResult(result, myOptions)
				}
			}
		}
	}
}

// Process takes a URL and extracts parameters
func Process(input string, myOptions *opt.Options) []Result {
	var results []Result

	// Check if input is a URL or file content
	if validate.IsUrl(input) {
		// Process as URL
		if myOptions.CrawlMode {
			// Use Katana for crawling
			results = append(results, SimpleCrawl(input, myOptions)...)
		} else {
			// Send HTTP request and analyze
			results = append(results, SendRequest(input, myOptions)...)
		}
	} else if strings.Contains(input, "{==MY=FILE=NAME==}") {
		// Process file content
		fileName := strings.Split(input, "{==MY=FILE=NAME==}")[0]
		body := strings.Split(input, "{==MY=FILE=NAME==}")[1]

		results = append(results, ProcessContent(fileName, body, myOptions)...)
	}

	return results
}

// ProcessContent extracts parameters from a content string
func ProcessContent(filename string, content string, myOptions *opt.Options) []Result {
	var results []Result

	// Determine content type based on filename extension
	contentType := getContentTypeFromFilename(filename)

	if myOptions.ExtractHTML && (contentType == "text/html" || strings.HasSuffix(filename, ".html") || strings.HasSuffix(filename, ".htm")) {
		results = append(results, ExtractHTMLParameters(content, filename)...)
	}

	if myOptions.ExtractJS && (contentType == "application/javascript" || strings.HasSuffix(filename, ".js")) {
		results = append(results, ExtractJSParameters(content, filename)...)
	}

	if myOptions.ExtractJSON && (contentType == "application/json" || strings.HasSuffix(filename, ".json")) {
		results = append(results, ExtractJSONParameters(content, filename)...)
	}

	if myOptions.ExtractPaths {
		results = append(results, ExtractPathParameters(filename, filename)...)
	}

	return results
}

// SendRequest sends an HTTP request to the URL and processes the response
func SendRequest(targetURL string, myOptions *opt.Options) []Result {
	var results []Result

	// Create HTTP client
	client := &http.Client{}

	// Create request
	req, err := http.NewRequest(myOptions.RequestHttpMethod, targetURL, strings.NewReader(myOptions.RequestBody))
	if err != nil {
		gologger.Warning().Msgf("Error creating request for %s: %s", targetURL, err.Error())
		return results
	}

	// Add default headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	// Add custom headers
	for _, header := range myOptions.CustomHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(parts[0], parts[1])
		}
	}

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		gologger.Warning().Msgf("Error sending request to %s: %s", targetURL, err.Error())
		return results
	}
	defer resp.Body.Close()

	// Process URL parameters
	results = append(results, ExtractURLParameters(targetURL, targetURL)...)

	// Process query parameters from the URL
	if myOptions.ExtractPaths {
		results = append(results, ExtractPathParameters(targetURL, targetURL)...)
	}

	// Read response body
	bodyBytes := make([]byte, 1024*1024*5) // 5MB buffer
	n, _ := resp.Body.Read(bodyBytes)
	body := string(bodyBytes[:n])

	contentType := resp.Header.Get("Content-Type")

	// Process HTML content
	if myOptions.ExtractHTML && strings.Contains(contentType, "text/html") {
		results = append(results, ExtractHTMLParameters(body, targetURL)...)
	}

	// Process JavaScript content
	if myOptions.ExtractJS && (strings.Contains(contentType, "javascript") || strings.Contains(contentType, "text/html")) {
		results = append(results, ExtractJSParameters(body, targetURL)...)
	}

	// Process JSON content
	if myOptions.ExtractJSON && strings.Contains(contentType, "application/json") {
		results = append(results, ExtractJSONParameters(body, targetURL)...)
	}

	return results
}

// ExtractURLParameters extracts parameters from a URL's query string
func ExtractURLParameters(urlStr string, sourceURL string) []Result {
	var results []Result

	// Parse the URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return results
	}

	// Extract query parameters
	params := parsedURL.Query()
	for param := range params {
		results = append(results, Result{
			Parameter:  param,
			Source:     "URL Query",
			URL:        sourceURL,
			Confidence: "High",
		})
	}

	// Also look for parameters using regex to catch malformed ones
	matches := regexQueryParams.FindAllStringSubmatch(parsedURL.RawQuery, -1)
	for _, match := range matches {
		if len(match) > 1 {
			paramName := match[1]
			// Check if already found
			found := false
			for _, r := range results {
				if r.Parameter == paramName {
					found = true
					break
				}
			}
			if !found {
				results = append(results, Result{
					Parameter:  paramName,
					Source:     "URL Query",
					URL:        sourceURL,
					Confidence: "High",
				})
			}
		}
	}

	return results
}

// ExtractPathParameters extracts potential parameters from URL paths
func ExtractPathParameters(urlStr string, sourceURL string) []Result {
	var results []Result

	// Parse the URL
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return results
	}

	// Look for explicit path parameters like "/user/{id}"
	matches := regexPathParams.FindAllStringSubmatch(parsedURL.Path, -1)
	for _, match := range matches {
		if len(match) > 1 {
			results = append(results, Result{
				Parameter:  match[1],
				Source:     "Path Parameter",
				URL:        sourceURL,
				Confidence: "Medium",
			})
		}
	}

	// Extract meaningful path segments
	segments := strings.Split(parsedURL.Path, "/")
	for _, segment := range segments {
		// Only consider segments that look like parameter names
		if len(segment) > 0 && regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]+$`).MatchString(segment) &&
			!regexp.MustCompile(`\.(html|php|js|css|jpg|png|gif)$`).MatchString(segment) {
			results = append(results, Result{
				Parameter:  segment,
				Source:     "Path Segment",
				URL:        sourceURL,
				Confidence: "Low",
			})
		}
	}

	return results
}

// ExtractHTMLParameters extracts parameters from HTML content
func ExtractHTMLParameters(content string, sourceURL string) []Result {
	var results []Result

	// Extract form input field names
	formFieldMatches := regexFormFields.FindAllStringSubmatch(content, -1)
	for _, match := range formFieldMatches {
		if len(match) > 1 {
			results = append(results, Result{
				Parameter:  match[1],
				Source:     "HTML Form Field",
				URL:        sourceURL,
				Confidence: "High",
			})
		}
	}

	// Extract form action URLs and their parameters
	formActionMatches := regexFormAction.FindAllStringSubmatch(content, -1)
	for _, match := range formActionMatches {
		if len(match) > 1 {
			actionURL := match[1]
			if strings.Contains(actionURL, "?") {
				// Extract parameters from the form action URL
				actionParams := ExtractURLParameters(actionURL, sourceURL)
				results = append(results, actionParams...)
			}
		}
	}

	// Extract comments for potential parameters
	if commentMatches := regexHtmlComments.FindAllStringSubmatch(content, -1); commentMatches != nil {
		for _, match := range commentMatches {
			if len(match) > 1 {
				commentContent := match[1]
				// Look for potential parameter patterns in comments
				paramMatches := regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9_]{2,})\b`).FindAllStringSubmatch(commentContent, -1)
				for _, paramMatch := range paramMatches {
					if len(paramMatch) > 1 {
						results = append(results, Result{
							Parameter:  paramMatch[1],
							Source:     "HTML Comment",
							URL:        sourceURL,
							Confidence: "Low",
						})
					}
				}
			}
		}
	}

	return results
}

// ExtractJSParameters extracts parameters from JavaScript content
func ExtractJSParameters(content string, sourceURL string) []Result {
	var results []Result

	// Extract URL parameters in JavaScript code
	jsParamMatches := regexJsParams.FindAllStringSubmatch(content, -1)
	for _, match := range jsParamMatches {
		if len(match) > 1 {
			results = append(results, Result{
				Parameter:  match[1],
				Source:     "JavaScript URL Parameter",
				URL:        sourceURL,
				Confidence: "Medium",
			})
		}
	}

	// Extract variable names
	jsVarMatches := regexJsVars.FindAllStringSubmatch(content, -1)
	for _, match := range jsVarMatches {
		if len(match) > 1 {
			results = append(results, Result{
				Parameter:  match[1],
				Source:     "JavaScript Variable",
				URL:        sourceURL,
				Confidence: "Low",
			})
		}
	}

	// Extract function parameters
	jsFuncMatches := regexJsFuncParams.FindAllStringSubmatch(content, -1)
	for _, match := range jsFuncMatches {
		if len(match) > 1 {
			// Split the parameters by comma and extract each parameter name
			params := strings.Split(match[1], ",")
			for _, param := range params {
				param = strings.TrimSpace(param)
				if len(param) > 0 {
					// If parameter has default value, extract just the name
					if strings.Contains(param, "=") {
						param = strings.TrimSpace(strings.SplitN(param, "=", 2)[0])
					}
					results = append(results, Result{
						Parameter:  param,
						Source:     "JavaScript Function Parameter",
						URL:        sourceURL,
						Confidence: "Low",
					})
				}
			}
		}
	}

	// Extract from comments
	jsCommentMatches := regexJsComments.FindAllStringSubmatch(content, -1)
	for _, match := range jsCommentMatches {
		if len(match) > 0 {
			commentContent := match[0]
			// Look for potential parameter patterns in comments
			paramMatches := regexp.MustCompile(`\b([a-zA-Z][a-zA-Z0-9_]{2,})\b`).FindAllStringSubmatch(commentContent, -1)
			for _, paramMatch := range paramMatches {
				if len(paramMatch) > 1 {
					results = append(results, Result{
						Parameter:  paramMatch[1],
						Source:     "JavaScript Comment",
						URL:        sourceURL,
						Confidence: "Low",
					})
				}
			}
		}
	}

	return results
}

// ExtractJSONParameters extracts parameters from JSON content
func ExtractJSONParameters(content string, sourceURL string) []Result {
	var results []Result

	// Extract JSON keys using regex
	jsonKeyMatches := regexJsonKeys.FindAllStringSubmatch(content, -1)
	for _, match := range jsonKeyMatches {
		if len(match) > 1 {
			results = append(results, Result{
				Parameter:  match[1],
				Source:     "JSON Key",
				URL:        sourceURL,
				Confidence: "Medium",
			})
		}
	}

	// Try to parse as JSON and extract keys
	var jsonObj interface{}
	if err := json.Unmarshal([]byte(content), &jsonObj); err == nil {
		results = append(results, extractJSONKeys(jsonObj, sourceURL)...)
	}

	return results
}

// extractJSONKeys recursively extracts keys from parsed JSON
func extractJSONKeys(jsonObj interface{}, sourceURL string) []Result {
	var results []Result

	switch v := jsonObj.(type) {
	case map[string]interface{}:
		for key, val := range v {
			results = append(results, Result{
				Parameter:  key,
				Source:     "JSON Key",
				URL:        sourceURL,
				Confidence: "Medium",
			})

			// Recursively process nested objects
			results = append(results, extractJSONKeys(val, sourceURL)...)
		}
	case []interface{}:
		for _, item := range v {
			results = append(results, extractJSONKeys(item, sourceURL)...)
		}
	}

	return results
}

// writeResult writes a parameter result to the output file and console
func writeResult(result Result, myOptions *opt.Options) {
	ParamSet.Lock()
	defer ParamSet.Unlock()

	// Skip if parameter has already been processed
	if ParamSet.params[result.Parameter] {
		return
	}

	// Mark parameter as processed
	ParamSet.params[result.Parameter] = true

	// Add to all results
	AllResults.Lock()
	AllResults.Results = append(AllResults.Results, result)
	AllResults.Unlock()

	// Write to console in silent mode
	if myOptions.SilentMode {
		if len(result.VulnTypes) > 0 {
			fmt.Printf("%s [%s] [%s]\n", result.Parameter, strings.Join(result.VulnTypes, ", "), result.Source)
		} else {
			fmt.Println(result.Parameter)
		}
	}

	// Write to file
	if myOptions.OutputFile != "parameters.txt" || !myOptions.SilentMode {
		file, err := os.OpenFile(myOptions.OutputFile, os.O_APPEND|os.O_WRONLY, 0666)
		if err != nil {
			gologger.Warning().Msgf("Error opening output file: %s", err.Error())
			return
		}

		if myOptions.OutputJSON {
			jsonData, _ := json.Marshal(result)
			_, err = fmt.Fprintln(file, string(jsonData))
		} else {
			_, err = fmt.Fprintln(file, result.Parameter)
		}

		if err != nil {
			gologger.Warning().Msgf("Error writing to output file: %s", err.Error())
		}

		file.Close()
	}
}

// getContentTypeFromFilename determines content type based on file extension
func getContentTypeFromFilename(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".html", ".htm":
		return "text/html"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".css":
		return "text/css"
	default:
		return "text/plain"
	}
}
