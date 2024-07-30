package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Results struct {
	params map[string]bool
	links  map[string]bool
	words  map[string]bool
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

func (r *Results) AddWord(word string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.words[word] = true
}

var (
	linkRegex = regexp.MustCompile(`(?:^|\"|'|\\n|\\r|\n|\r|\s)(((?:[a-zA-Z]{1,10}:\/\/|\/\/)([^\"'\/\s]{1,255}\.[a-zA-Z]{2,24}|localhost)[^\"'\n\s]{0,255})|((?:\/|\.\.\/|\.\/)[^\"'><,;| *()(%%$^\/\\\[\]][^\"'><,;|()\s]{1,255})|([a-zA-Z0-9_\-\/]{1,}\/[a-zA-Z0-9_\-\/\.]{1,255}\.(?:[a-zA-Z]{1,4}|[a-zA-Z0-9_\-]{1,255})(?:[\?|\/][^\"|']{0,}|))|([a-zA-Z0-9_\-\.]{1,255}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\?[^\"|^']{0,255}|)))(?:\"|'|\\n|\\r|\n|\r|\s|$)|(\{[^\}]+\})|("[a-zA-Z0-9_]+":)`)

	wordRegex = regexp.MustCompile(`\b\w+\b`)

	paramRegex = regexp.MustCompile(`(?:^|[?&])([^=&]+)=([^&]*)|("[a-zA-Z0-9_]+"\s*:\s*"[^"]*")|('[a-zA-Z0-9_]+'\s*:\s*'[^']*')`)

	allowedContentTypes = map[string]bool{
		"text/html":              true,
		"application/json":       true,
		"text/plain":             true,
		"application/javascript": true,
		"text/javascript":        true,
	}
)

func FetchHTML(url string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}

func ExtractInfo(htmlContent string, results *Results) {
	links := linkRegex.FindAllString(htmlContent, -1)
	for _, link := range links {
		results.AddLink(strings.TrimSpace(link))
	}

	words := wordRegex.FindAllString(htmlContent, -1)
	for _, word := range words {
		if len(word) > 2 { // Only add words with 3 or more characters
			results.AddWord(strings.TrimSpace(word))
		}
	}

	params := paramRegex.FindAllStringSubmatch(htmlContent, -1)
	for _, param := range params {
		if len(param) > 1 {
			paramName := strings.TrimSpace(param[1])
			if len(paramName) > 0 {
				results.AddParam(paramName)
			}
			if len(param) > 2 {
				paramValue := strings.TrimSpace(param[2])
				if len(paramValue) > 0 {
					results.AddParam(paramValue)
				}
			}
		}
	}
}

func shouldProcessContentType(contentType string) bool {
	for allowed := range allowedContentTypes {
		if strings.Contains(contentType, allowed) {
			return true
		}
	}
	return false
}

func isInScope(baseURL, foundURL string) bool {
	baseU, err := url.Parse(baseURL)
	if err != nil {
		return false
	}

	foundU, err := url.Parse(foundURL)
	if err != nil {
		return false
	}

	baseDomain := getSecondLevelDomain(baseU.Hostname())
	foundDomain := getSecondLevelDomain(foundU.Hostname())

	return baseDomain == foundDomain
}

func getSecondLevelDomain(hostname string) string {
	parts := strings.Split(hostname, ".")
	if len(parts) > 1 {
		return parts[len(parts)-2]
	}
	return hostname
}

func processURL(baseURL string, results *Results, wg *sync.WaitGroup) {
	defer wg.Done()

	htmlContent, err := FetchHTML(baseURL)
	if err != nil {
		fmt.Printf("Error fetching %s: %v\n", baseURL, err)
		return
	}

	ExtractInfo(htmlContent, results)

	// Process found links
	for link := range results.links {
		if isInScope(baseURL, link) {
			wg.Add(1)
			go processURL(link, results, wg)
		}
	}
}

func main() {
	inputFile := flag.String("i", "", "input file containing URLs")
	outputFile := flag.String("o", "", "output file to save results")
	flag.Parse()

	var urls []string
	results := &Results{
		params: make(map[string]bool),
		links:  make(map[string]bool),
		words:  make(map[string]bool),
	}

	if *inputFile != "" {
		content, err := os.ReadFile(*inputFile)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}
		urls = strings.Fields(string(content))
	} else {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			urls = append(urls, scanner.Text())
		}
	}

	var wg sync.WaitGroup
	for _, url := range urls {
		wg.Add(1)
		go processURL(url, results, &wg)
	}
	wg.Wait()

	// Prepare output
	output := strings.Join(getKeys(results.params), "\n") + "\n" +
		strings.Join(getKeys(results.words), "\n")

	if *outputFile != "" {
		err := os.WriteFile(*outputFile, []byte(output), 0644)
		if err != nil {
			fmt.Printf("Error writing to file: %v\n", err)
		}
	} else {
		fmt.Println(output)
	}
}

func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
