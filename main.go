package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/chromedp/cdproto/dom"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"golang.org/x/time/rate"
)

type Config struct {
	URL           string
	MaxDepth      int
	RateLimit     int
	Method        string
	Data          string
	Headers       []string
	Proxy         string
	ContentType   string
	InputFile     string
	OutputFile    string
	OutputFormat  string
	MaxConcurrent int
	UseJavaScript bool
}

type Results struct {
	params map[string]bool
	links  map[string]bool
	mu     sync.Mutex
}

func (r *Results) AddParam(param string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.params[param] = true
}

func (r *Results) AddLink(link string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.links[link] = true
}

func contains(slice []string, item string) bool {
	for _, a := range slice {
		if a == item {
			return true
		}
	}
	return false
}

var (
	linkRegex = regexp.MustCompile(`(?:^|\"|'|\\n|\\r|\n|\r|\s)(((?:[a-zA-Z]{1,10}:\/\/|\/\/)([^\"'\/\s]{1,255}\.[a-zA-Z]{2,24}|localhost)[^\"'\n\s]{0,255})|((?:\/|\.\.\/|\.\/)[^\"'><,;| *()(%%$^\/\\\[\]][^\"'><,;|()\s]{1,255})|([a-zA-Z0-9_\-\/]{1,}\/[a-zA-Z0-9_\-\/\.]{1,255}\.(?:[a-zA-Z]{1,4}|[a-zA-Z0-9_\-]{1,255})(?:[\?|\/][^\"|']{0,}|))|([a-zA-Z0-9_\-\.]{1,255}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^\"|^']{0,255}|)))(?:\"|'|\\n|\\r|\n|\r|\s|$)`)
)

func main() {
	config := parseFlags()
	results := &Results{
		params: make(map[string]bool),
		links:  make(map[string]bool),
	}

	urls := getURLs(config.InputFile)
	if len(urls) == 0 && config.URL != "" {
		urls = append(urls, config.URL)
	}

	limiter := rate.NewLimiter(rate.Every(time.Second/time.Duration(config.RateLimit)), 1)

	// Create a new chrome instance
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("ignore-certificate-errors", true),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocCtx)
	defer cancel()

	var wg sync.WaitGroup
	urlChan := make(chan string, len(urls))
	for _, u := range urls {
		urlChan <- u
	}
	close(urlChan)

	for i := 0; i < config.MaxConcurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urlChan {
				crawl(ctx, url, results, 0, config, limiter)
			}
		}()
	}
	wg.Wait()

	outputResults(results, config)
}

func parseFlags() *Config {
	config := &Config{}
	flag.StringVar(&config.URL, "url", "", "Target URL")
	flag.IntVar(&config.MaxDepth, "depth", 5, "Maximum crawl depth")
	flag.IntVar(&config.RateLimit, "rate", 10, "Rate limit (requests per second)")
	flag.StringVar(&config.Method, "method", "GET", "HTTP method")
	flag.StringVar(&config.Data, "data", "", "Data for POST requests")
	flag.StringVar(&config.Proxy, "proxy", "", "HTTP proxy to use")
	flag.StringVar(&config.ContentType, "content-type", "", "Specific content type to process")
	flag.StringVar(&config.InputFile, "input", "", "Input file containing URLs (one per line)")
	flag.StringVar(&config.OutputFile, "output", "output.txt", "Output file")
	flag.StringVar(&config.OutputFormat, "format", "text", "Output format (text or json)")
	flag.IntVar(&config.MaxConcurrent, "concurrent", 10, "Maximum number of concurrent requests")
	flag.BoolVar(&config.UseJavaScript, "js", false, "Use JavaScript rendering for crawling")
	var headers multiFlag
	flag.Var(&headers, "H", "Custom headers (can be used multiple times)")
	config.Headers = headers

	flag.Parse()
	return config
}

type multiFlag []string

func (f *multiFlag) String() string {
	return strings.Join(*f, ", ")
}

func (f *multiFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func getURLs(inputFile string) []string {
	var urls []string

	if inputFile != "" {
		file, err := os.Open(inputFile)
		if err != nil {
			log.Fatalf("Error opening input file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			urls = append(urls, strings.TrimSpace(scanner.Text()))
		}
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			urls = append(urls, strings.TrimSpace(scanner.Text()))
		}
	}

	return urls
}

func crawl(ctx context.Context, baseURL string, results *Results, depth int, config *Config, limiter *rate.Limiter) {
	if depth > config.MaxDepth {
		return
	}

	if err := limiter.Wait(context.Background()); err != nil {
		log.Printf("Rate limit error: %v\n", err)
		return
	}

	body, links, err := fetchURL(ctx, baseURL, config, results)
	if err != nil {
		log.Printf("Error fetching %s: %v\n", baseURL, err)
		return
	}

	extractInfo(baseURL, body, results)

	// Process discovered links
	for _, link := range links {
		absoluteURL := resolveURL(baseURL, link)
		if isValidLink(absoluteURL) && isInScope(baseURL, absoluteURL) {
			if _, exists := results.links[absoluteURL]; !exists {
				results.AddLink(absoluteURL)
				crawl(ctx, absoluteURL, results, depth+1, config, limiter)
			}
		}
	}
}

func fetchURL(ctx context.Context, url string, config *Config, results *Results) (string, []string, error) {
	var body string
	var links []string

	err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.WaitReady("body"),
		chromedp.ActionFunc(func(ctx context.Context) error {
			node, err := dom.GetDocument().Do(ctx)
			if err != nil {
				return err
			}
			body, err = dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
			return err
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			// Extract links and parameters using JavaScript
			var result string
			err := chromedp.Evaluate(`
                (function() {
                    let data = {links: [], params: []};
                    
                    // Extract links
                    data.links = Array.from(document.querySelectorAll('a')).map(a => a.href);
                    
                    // Extract input names and ids
                    document.querySelectorAll('input, textarea, select').forEach(el => {
                        if (el.name) data.params.push(el.name);
                        if (el.id) data.params.push(el.id);
                    });
                    
                    // Extract form action URLs
                    document.querySelectorAll('form').forEach(form => {
                        if (form.action) data.links.push(form.action);
                    });
                    
                    // Extract JavaScript variables and function names
                    let scriptContent = Array.from(document.scripts).map(script => script.textContent).join('\\n');
                    let varRegex = /(?:var|let|const)\\s+(\\w+)/g;
                    let funcRegex = /function\\s+(\\w+)/g;
                    let match;
                    while ((match = varRegex.exec(scriptContent)) !== null) {
                        data.params.push(match[1]);
                    }
                    while ((match = funcRegex.exec(scriptContent)) !== null) {
                        data.params.push(match[1]);
                    }
                    
                    // Extract potential parameters from URL paths
                    document.querySelectorAll('a[href]').forEach(a => {
                        let path = new URL(a.href).pathname;
                        path.split('/').forEach(segment => {
                            if (segment && !data.params.includes(segment)) {
                                data.params.push(segment);
                            }
                        });
                    });
                    
                    // Extract potential JSON keys
                    let jsonRegex = /{(?:[^{}]|({[^{}]*}))*}/g;
                    let jsonMatches = scriptContent.match(jsonRegex) || [];
                    jsonMatches.forEach(jsonStr => {
                        try {
                            let jsonObj = JSON.parse(jsonStr);
                            Object.keys(jsonObj).forEach(key => {
                                if (!data.params.includes(key)) {
                                    data.params.push(key);
                                }
                            });
                        } catch (e) {
                            // Not valid JSON, ignore
                        }
                    });
                    
                    // Extract inline event handlers
                    ['onclick', 'onsubmit', 'onload', 'onchange'].forEach(attr => {
                        document.querySelectorAll('[' + attr + ']').forEach(el => {
                            let content = el.getAttribute(attr);
                            let funcCallRegex = /(\\w+)\\s*\\(/g;
                            while ((match = funcCallRegex.exec(content)) !== null) {
                                if (!data.params.includes(match[1])) {
                                    data.params.push(match[1]);
                                }
                            }
                        });
                    });
                    
                    return JSON.stringify(data);
                })()
            `, &result).Do(ctx)
			if err != nil {
				return err
			}

			var data struct {
				Links  []string `json:"links"`
				Params []string `json:"params"`
			}
			err = json.Unmarshal([]byte(result), &data)
			if err != nil {
				return err
			}

			links = data.Links

			// Add extracted params to results
			for _, param := range data.Params {
				results.AddParam(param)
			}

			return nil
		}),
	)

	return body, links, err
}

func fetchWithoutJavaScript(targetURL string, config *Config) (string, error) {
	client := &http.Client{
		Timeout: 60 * time.Second,
	}

	if config.Proxy != "" {
		proxyURL, err := url.Parse(config.Proxy)
		if err != nil {
			return "", fmt.Errorf("invalid proxy URL: %v", err)
		}
		client.Transport = &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	} else {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	req, err := http.NewRequest(strings.ToUpper(config.Method), targetURL, strings.NewReader(config.Data))
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Connection", "close")

	if config.Method == "POST" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	for _, header := range config.Headers {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}

func fetchWithJavaScript(url string, config *Config) (string, error) {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	var body string
	err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate(url),
		chromedp.WaitVisible("body", chromedp.ByQuery),
		chromedp.OuterHTML("html", &body),
	)

	return body, err
}

func extractInfo(baseURL, body string, results *Results) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		log.Printf("Error parsing HTML: %v\n", err)
		return
	}

	// Extract from <input> tags
	doc.Find("input, textarea, select").Each(func(i int, s *goquery.Selection) {
		if id, exists := s.Attr("id"); exists {
			results.AddParam(id)
		}
		if name, exists := s.Attr("name"); exists {
			results.AddParam(name)
		}
	})

	// Extract from <form> tags
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		if action, exists := s.Attr("action"); exists {
			processHref(action, results)
		}
	})

	// Extract from <a> tags
	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			processHref(href, results)
		}
	})

	// Extract JavaScript variables and JSON keys
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		extractJavaScriptInfo(s.Text(), results)
	})

	// Extract from inline event handlers
	doc.Find("*").Each(func(i int, s *goquery.Selection) {
		for _, attrName := range []string{"onclick", "onsubmit", "onload", "onchange"} {
			if attrValue, exists := s.Attr(attrName); exists {
				extractJavaScriptInfo(attrValue, results)
			}
		}
	})
}

func processHref(href string, results *Results) {
	u, err := url.Parse(href)
	if err != nil {
		return
	}

	// Extract path components
	pathParts := strings.Split(u.Path, "/")
	for _, part := range pathParts {
		if part != "" {
			results.AddParam(part)
		}
	}

	// Extract query parameters
	queryParams := u.Query()
	for param := range queryParams {
		results.AddParam(param)
	}
}

func extractJavaScriptInfo(content string, results *Results) {
	// Extract potential variable declarations
	varRegex := regexp.MustCompile(`(?:var|let|const)\s+(\w+)`)
	matches := varRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			results.AddParam(match[1])
		}
	}

	// Extract function names
	funcRegex := regexp.MustCompile(`function\s+(\w+)`)
	matches = funcRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			results.AddParam(match[1])
		}
	}

	// Extract object property names
	propRegex := regexp.MustCompile(`(\w+)\s*:`)
	matches = propRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			results.AddParam(match[1])
		}
	}

	// Extract JSON-like structures
	jsonRegex := regexp.MustCompile(`\{(?:[^{}]|(\{[^{}]*\}))*\}`)
	jsonMatches := jsonRegex.FindAllString(content, -1)
	for _, jsonStr := range jsonMatches {
		var jsonObj map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &jsonObj); err == nil {
			for key := range jsonObj {
				results.AddParam(key)
			}
		}
	}
}

func extractJSFromContent(content string, results *Results) {
	// Extract potential variable declarations
	varRegex := regexp.MustCompile(`(?:var|let|const)\s+(\w+)`)
	matches := varRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			results.AddParam(match[1])
		}
	}

	// Extract function names
	funcRegex := regexp.MustCompile(`function\s+(\w+)`)
	matches = funcRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			results.AddParam(match[1])
		}
	}

	// Extract object property names
	propRegex := regexp.MustCompile(`(\w+)\s*:`)
	matches = propRegex.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			results.AddParam(match[1])
		}
	}

	// Extract JSON-like structures
	jsonRegex := regexp.MustCompile(`\{(?:[^{}]|(\{[^{}]*\}))*\}`)
	jsonMatches := jsonRegex.FindAllString(content, -1)
	for _, jsonStr := range jsonMatches {
		var jsonObj map[string]interface{}
		if err := json.Unmarshal([]byte(jsonStr), &jsonObj); err == nil {
			for key := range jsonObj {
				results.AddParam(key)
			}
		}
	}
}

func extractLinks(body string) []string {
	var links []string
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		log.Printf("Error parsing HTML for link extraction: %v\n", err)
		return links
	}

	doc.Find("a").Each(func(i int, s *goquery.Selection) {
		if href, exists := s.Attr("href"); exists {
			links = append(links, href)
		}
	})

	return links
}

func isValidLink(link string) bool {
	u, err := url.Parse(link)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func isInScope(baseURL, link string) bool {
	base, err := url.Parse(baseURL)
	if err != nil {
		return false
	}

	u, err := url.Parse(link)
	if err != nil {
		return false
	}

	return base.Hostname() == u.Hostname()
}

func resolveURL(base, ref string) string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return baseURL.ResolveReference(refURL).String()
}

func outputResults(results *Results, config *Config) {
	uniqueParams := make(map[string]bool)
	for param := range results.params {
		uniqueParams[param] = true
	}

	if config.OutputFormat == "json" {
		outputJSON(uniqueParams, results.links, config.OutputFile)
	} else {
		outputText(uniqueParams, results.links, config.OutputFile)
	}
}

func outputJSON(params map[string]bool, links map[string]bool, outputFile string) {
	output := struct {
		Params []string `json:"params"`
		Links  []string `json:"links"`
	}{
		Params: make([]string, 0, len(params)),
		Links:  make([]string, 0, len(links)),
	}

	for param := range params {
		output.Params = append(output.Params, param)
	}
	for link := range links {
		output.Links = append(output.Links, link)
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		log.Fatalf("Error marshalling JSON: %v", err)
	}

	err = os.WriteFile(outputFile, jsonData, 0644)
	if err != nil {
		log.Fatalf("Error writing output file: %v", err)
	}

	fmt.Printf("Results written to %s\n", outputFile)
}

func outputText(params map[string]bool, links map[string]bool, outputFile string) {
	file, err := os.Create(outputFile)
	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	writer.WriteString("Parameters:\n")
	for param := range params {
		writer.WriteString(fmt.Sprintf("%s\n", param))
	}

	writer.WriteString("\nLinks:\n")
	for link := range links {
		writer.WriteString(fmt.Sprintf("%s\n", link))
	}

	writer.Flush()
	fmt.Printf("Results written to %s\n", outputFile)
}
