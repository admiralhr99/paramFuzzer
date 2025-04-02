package validate

import (
	"github.com/admiralhr99/paramFuzzer/funcs/opt"
	errorutil "github.com/projectdiscovery/utils/errors"
	"net/url"
	"strings"
)

func Options(options *opt.Options) error {
	if options.InputUrls == "" && options.InputDIR == "" && options.InputHttpRequest == "" {
		return errorutil.New("input is empty! Use -u, -dir, or -r flag")
	}

	if options.MaxLength <= 0 {
		return errorutil.New("maximum length of the parameter (-max-length) must be greater than 0")
	}

	if options.CrawlMode && options.MaxDepth <= 0 && options.CrawlDuration.Seconds() <= 0 {
		return errorutil.New("either max-depth or crawl-duration must be specified when using crawl mode")
	}

	if options.InputDIR != "" && options.InputUrls != "" {
		return errorutil.New("online mode (-url) and offline mode (-directory) cannot be used together")
	}

	if options.InputDIR != "" && options.CrawlMode {
		return errorutil.New("crawl mode (-crawl) and offline mode (-directory) cannot be used together")
	}

	if strings.ToUpper(options.RequestHttpMethod) != "GET" && options.CrawlMode {
		return errorutil.New("crawl mode (-crawl) works only with the GET HTTP request method")
	}

	if strings.ToUpper(options.RequestHttpMethod) != "GET" && options.Headless {
		return errorutil.New("headless mode (-headless) works only with the GET HTTP request method")
	}

	if options.RequestBody != "" && options.CrawlMode {
		return errorutil.New("crawl mode (-crawl) works only with the GET HTTP request method")
	}

	if options.ProxyUrl != "" {
		u, err := url.Parse(options.ProxyUrl)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return errorutil.New("the proxy URL (-proxy) is invalid")
		}
	}

	if options.MinLength < 0 {
		return errorutil.New("the minimum length (-min-length) must be greater than or equal to 0")
	}

	if options.MinLength >= options.MaxLength {
		return errorutil.New("the maximum length (-max-length) must be greater than the minimum length (-min-length)")
	}

	return nil
}

// IsUrl checks if the provided string is a valid URL
func IsUrl(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// Clear filters out unwanted URLs based on extensions
func Clear(links []string) []string {
	badExtensions := []string{
		".css", ".jpg", ".jpeg", ".png", ".svg", ".img", ".gif", ".exe", ".mp4", ".flv", ".pdf", ".doc", ".ogv", ".webm", ".wmv",
		".webp", ".mov", ".mp3", ".m4a", ".m4p", ".ppt", ".pptx", ".scss", ".tif", ".tiff", ".ttf", ".otf", ".woff", ".woff2", ".bmp",
		".ico", ".eot", ".htc", ".swf", ".rtf", ".image", ".rf"}
	var result []string

	for _, link := range links {
		isGoodUrl := true
		u, _ := url.Parse(link)

		for _, ext := range badExtensions {
			if strings.HasSuffix(strings.ToLower(u.Path), ext) {
				isGoodUrl = false
				break
			}
		}

		if !IsUrl(link) {
			isGoodUrl = false
		}

		if isGoodUrl {
			result = append(result, link)
		}
	}
	return result
}
