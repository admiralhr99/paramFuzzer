package validate

import (
	"github.com/admiralhr99/paramFuzzer/funcs/opt"
	errorutil "github.com/projectdiscovery/utils/errors"
	"net/url"
	"os"
	"strings"
)

func Options(options *opt.Options) error {
	// Check if there is input from stdin
	info, err := os.Stdin.Stat()
	stdinHasData := (err == nil && (info.Mode()&os.ModeCharDevice) == 0)

	// Only require input if stdin is not being used
	if options.InputUrls == "" && options.InputDIR == "" && options.InputHttpRequest == "" && !stdinHasData {
		return errorutil.New("input is empty! Provide a URL, file, directory, or pipe data from stdin")
	}
	if options.MaxLength <= 0 {
		return errorutil.New("maximum length of the parameter (-max-length) must be greater than 0.")
	}
	if options.MaxDepth <= 0 && options.CrawlDuration.Seconds() <= 0 {
		return errorutil.New("either max-depth or crawl-duration must be specified")
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
	if strings.ToUpper(options.RequestHttpMethod) != "GET" && options.Headless {
		return errorutil.New("headless mode (-headless) works only with the GET HTTP request method")
	}
	if options.ProxyUrl != "" {
		u, err := url.Parse(options.ProxyUrl)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return errorutil.New("the proxy URL (-proxy) is invalid.")
		}
	}
	if options.MaxLength <= 0 {
		return errorutil.New("the maximum length (-max-length) must be greater than 0.")
	}
	if options.MinLength < 0 {
		return errorutil.New("the minimum length (-min-length) must be greater than 0.")
	}
	if options.MinLength >= options.MaxLength {
		return errorutil.New("The maximum length (-max-length) must be greater than the minimum length (-min-length).")
	}
	return nil
}
