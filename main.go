package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// FetchHTML fetches HTML content from a given URL
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

// ExtractHTMLInfo extracts information from HTML content
func ExtractHTMLInfo(htmlContent string) []string {
	var output []string
	doc := html.NewTokenizer(strings.NewReader(htmlContent))
	for {
		tt := doc.Next()
		switch tt {
		case html.ErrorToken:
			return output
		case html.StartTagToken, html.SelfClosingTagToken:
			t := doc.Token()
			switch t.Data {
			case "input":
				for _, attr := range t.Attr {
					if attr.Key == "id" || attr.Key == "name" {
						output = append(output, attr.Val)
					}
				}
			case "a":
				for _, attr := range t.Attr {
					if attr.Key == "href" {
						params := strings.Split(attr.Val, "?")
						if len(params) > 1 {
							queryParts := strings.Split(params[1], "&")
							for _, part := range queryParts {
								kv := strings.Split(part, "=")
								if len(kv) > 0 {
									output = append(output, kv[0])
								}
							}
						}
					}
				}
			}
		}
	}
}

// ExtractJSInfo extracts information from JavaScript content
func ExtractJSInfo(jsContent string) []string {
	var output []string
	varNameRegex := regexp.MustCompile(`(?:var|let|const)\s+(\w+)\s*=`)
	varNames := varNameRegex.FindAllStringSubmatch(jsContent, -1)
	for _, name := range varNames {
		output = append(output, name[1])
	}
	objectKeyRegex := regexp.MustCompile(`[,{]\s*["']?(\w+)["']?\s*:`)
	objectKeys := objectKeyRegex.FindAllStringSubmatch(jsContent, -1)
	for _, key := range objectKeys {
		output = append(output, key[1])
	}
	return output
}

func main() {
	inputFile := flag.String("i", "", "input file containing URLs")
	outputFile := flag.String("o", "", "output file to save results")
	mode := flag.String("m", "html", "parsing mode: html, js, or all")
	flag.Parse()

	var urls []string
	uniqueOutput := make(map[string]struct{})

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
	resultChan := make(chan []string, len(urls))

	for _, url := range urls {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			var tempOutput []string
			if *mode == "html" || *mode == "all" {
				htmlContent, err := FetchHTML(url)
				if err == nil {
					tempOutput = append(tempOutput, ExtractHTMLInfo(htmlContent)...)
				}
			}
			if *mode == "js" || *mode == "all" {
				jsContent, err := FetchHTML(url)
				if err == nil {
					tempOutput = append(tempOutput, ExtractJSInfo(jsContent)...)
				}
			}
			resultChan <- tempOutput
		}(url)
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for tempOutput := range resultChan {
		for _, item := range tempOutput {
			uniqueOutput[item] = struct{}{}
		}
	}

	var output []string
	for key := range uniqueOutput {
		// Remove any numbers from the final output
		if _, err := strconv.Atoi(key); err != nil {
			output = append(output, key)
		}
	}

	result := strings.Join(output, "\n")
	if *outputFile != "" {
		err := os.WriteFile(*outputFile, []byte(result), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to file: %v\n", err)
		}
	} else {
		fmt.Println(result)
	}
}
