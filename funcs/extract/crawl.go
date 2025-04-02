package extract

import (
	"github.com/admiralhr99/paramFuzzer/funcs/opt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	"github.com/projectdiscovery/katana/pkg/output"
	"github.com/projectdiscovery/katana/pkg/types"
	"math"
	"net/url"
	"strings"
)

// SimpleCrawl uses Katana to crawl a website and extract parameters
func SimpleCrawl(link string, myOptions *opt.Options) []Result {
	var allResults []Result

	gologger.Info().Msgf("Starting crawl on: %s", link)

	options := &types.Options{
		MaxDepth:               myOptions.MaxDepth,
		ScrapeJSResponses:      true,
		ScrapeJSLuiceResponses: true,
		CrawlDuration:          myOptions.CrawlDuration,
		Timeout:                10,
		Retries:                1,
		Headless:               myOptions.Headless,
		UseInstalledChrome:     false,
		ShowBrowser:            false,
		HeadlessNoSandbox:      true,
		HeadlessNoIncognito:    false,
		TlsImpersonate:         false,
		CustomHeaders:          myOptions.CustomHeaders,
		IgnoreQueryParams:      false,
		Scope:                  nil,
		OutOfScope:             nil,
		Delay:                  myOptions.Delay,
		NoScope:                false,
		DisplayOutScope:        false,
		OutputMatchRegex:       nil,
		OutputFilterRegex:      nil,
		KnownFiles:             "all",
		ExtensionsMatch:        nil,
		ExtensionFilter: []string{
			".css", ".jpg", ".jpeg", ".png", ".svg", ".img", ".gif", ".exe", ".mp4", ".flv", ".pdf", ".doc", ".ogv", ".webm", ".wmv",
			".webp", ".mov", ".mp3", ".m4a", ".m4p", ".ppt", ".pptx", ".scss", ".tif", ".tiff", ".ttf", ".otf", ".woff", ".woff2", ".bmp",
			".ico", ".eot", ".htc", ".swf", ".rtf", ".image", ".rf"},
		Silent:           !myOptions.VerboseMode,
		FieldScope:       "rdn",
		BodyReadSize:     math.MaxInt,
		DisableRedirects: false,
		RateLimit:        150,
		Strategy:         "depth-first",
		OnResult: func(result output.Result) {
			if result.HasResponse() {
				// Get URL parameters
				if u, err := url.Parse(result.Request.URL); err == nil {
					// Extract URL parameters
					if u.RawQuery != "" {
						for param := range u.Query() {
							allResults = append(allResults, Result{
								Parameter:  param,
								Source:     "URL Query",
								URL:        result.Request.URL,
								Confidence: "High",
							})
						}
					}

					// Extract path parameters if enabled
					if myOptions.ExtractPaths {
						pathResults := ExtractPathParameters(result.Request.URL, result.Request.URL)
						allResults = append(allResults, pathResults...)
					}
				}

				// Process the response body based on content type
				contentType := result.Response.Resp.Header.Get("Content-Type")

				// Process HTML content
				if myOptions.ExtractHTML && strings.Contains(contentType, "text/html") {
					htmlResults := ExtractHTMLParameters(result.Response.Body, result.Request.URL)
					allResults = append(allResults, htmlResults...)
				}

				// Process JavaScript content
				if myOptions.ExtractJS && (strings.Contains(contentType, "javascript") || strings.Contains(contentType, "text/html")) {
					jsResults := ExtractJSParameters(result.Response.Body, result.Request.URL)
					allResults = append(allResults, jsResults...)
				}

				// Process JSON content
				if myOptions.ExtractJSON && strings.Contains(contentType, "application/json") {
					jsonResults := ExtractJSONParameters(result.Response.Body, result.Request.URL)
					allResults = append(allResults, jsonResults...)
				}

				if myOptions.VerboseMode {
					gologger.Info().Msgf("Processed: %s", result.Request.URL)
				}
			}
		},
	}

	if myOptions.ProxyUrl != "" {
		options.Proxy = myOptions.ProxyUrl
	}

	crawlerOptions, err := types.NewCrawlerOptions(options)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	defer crawlerOptions.Close()

	crawler, err := standard.New(crawlerOptions)
	if err != nil {
		gologger.Fatal().Msg(err.Error())
	}
	defer crawler.Close()

	err = crawler.Crawl(link)
	if err != nil {
		gologger.Warning().Msgf("Could not crawl %s: %s", link, err.Error())
	}

	gologger.Info().Msgf("Crawl completed for: %s", link)
	gologger.Info().Msgf("Found %d potential parameters", len(allResults))

	return allResults
}
