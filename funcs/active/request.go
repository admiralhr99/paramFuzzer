// active/request.go - Fixed version with better error handling

package active

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/admiralhr99/paramFuzzer/funcs/opt"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/projectdiscovery/gologger"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// parseHeader safely parses a header string in "Key: Value" format
func parseHeader(header string) (string, string, error) {
	parts := strings.SplitN(header, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid header format: %s", header)
	}
	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	if key == "" {
		return "", "", fmt.Errorf("empty header key in: %s", header)
	}

	return key, value, nil
}

func SendRequest(link string, myOptions *opt.Options) (*http.Response, string) {
	client := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:    100,
			IdleConnTimeout: 30 * time.Second,
		},
	}

	// Set proxy if provided
	if myOptions.ProxyUrl != "" {
		pUrl, err := url.Parse(myOptions.ProxyUrl)
		if err != nil {
			gologger.Warning().Msgf("Invalid proxy URL: %s", err)
		} else {
			client.Transport.(*http.Transport).Proxy = http.ProxyURL(pUrl)
		}
	}

	req, err := http.NewRequest(strings.ToUpper(myOptions.RequestHttpMethod), link, bytes.NewBuffer([]byte(myOptions.RequestBody)))
	if err != nil {
		gologger.Warning().Msgf("Failed to create request for %s: %s", link, err)
		return &http.Response{}, ""
	}

	// Set default headers if no custom request is provided
	if myOptions.InputHttpRequest == "" {
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")
		req.Header.Set("Sec-Fetch-User", "?1")
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0")
		req.Header.Set("Referer", link)
	}

	// Add custom headers
	if len(myOptions.CustomHeaders) != 0 {
		for _, v := range myOptions.CustomHeaders {
			key, value, err := parseHeader(v)
			if err != nil {
				gologger.Warning().Msgf("Skipping invalid header: %s", err)
				continue
			}
			req.Header.Set(key, value)
		}
	}

	res, err := client.Do(req)
	if err != nil {
		gologger.Warning().Msgf("Request failed for %s: %s", link, err)
		return &http.Response{}, ""
	}
	defer res.Body.Close()

	resByte, err := io.ReadAll(res.Body)
	if err != nil {
		gologger.Warning().Msgf("Failed to read response body for %s: %s", link, err)
		return res, ""
	}

	// Apply delay if specified
	if myOptions.Delay > 0 {
		time.Sleep(time.Duration(myOptions.Delay) * time.Second)
	}

	return res, string(resByte)
}

func HeadlessBrowser(link string, myOptions *opt.Options) string {
	// Chrome flags for better compatibility
	options := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("disable-infobars", true),
		chromedp.Flag("headless", true),
		chromedp.Flag("enable-automation", false),
		chromedp.Flag("password-store", false),
		chromedp.Flag("disable-extensions", false),
		chromedp.Flag("ignore-certificate-errors", "1"),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-features", "VizDisplayCompositor"),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
	)

	// Add proxy if provided
	if myOptions.ProxyUrl != "" {
		options = append(options, chromedp.Flag("proxy-server", myOptions.ProxyUrl))
	}

	// Prepare headers
	headers := map[string]interface{}{}
	if myOptions.InputHttpRequest == "" {
		headers = map[string]interface{}{
			"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/114.0",
			"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"Accept-Language": "en-US,en;q=0.5",
			"Sec-Fetch-Dest":  "document",
			"Sec-Fetch-Mode":  "navigate",
			"Sec-Fetch-Site":  "none",
			"Sec-Fetch-User":  "?1",
			"Referer":         link,
		}
	}

	// Add custom headers
	if len(myOptions.CustomHeaders) > 0 {
		for _, head := range myOptions.CustomHeaders {
			key, value, err := parseHeader(head)
			if err != nil {
				gologger.Warning().Msgf("Skipping invalid header in headless mode: %s", err)
				continue
			}
			headers[key] = value
		}
	}

	// Create context with timeout
	allocContext, cancel := chromedp.NewExecAllocator(context.Background(), options...)
	defer cancel()

	ctx, cancel := chromedp.NewContext(allocContext)
	defer cancel()

	// Set a reasonable timeout for the entire operation
	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Set up network interception to add custom headers
	err := chromedp.Run(ctx, network.Enable(), network.SetExtraHTTPHeaders(headers))
	if err != nil {
		gologger.Warning().Msgf("Failed to set headers in headless browser: %s", err)
		return ""
	}

	// Navigate to the URL and retrieve the page DOM
	var htmlContent string
	err = chromedp.Run(ctx,
		chromedp.Navigate(link),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(2*time.Second), // Wait for JS to execute
		chromedp.OuterHTML("html", &htmlContent),
	)

	if err != nil {
		gologger.Warning().Msgf("Headless browser failed for %s: %s", link, err)
		return ""
	}

	return htmlContent
}
