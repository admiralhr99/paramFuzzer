package main

import (
	"github.com/admiralhr99/paramFuzzer/funcs/extract"
	"github.com/admiralhr99/paramFuzzer/funcs/opt"
	"github.com/admiralhr99/paramFuzzer/funcs/utils"
	"github.com/admiralhr99/paramFuzzer/funcs/validate"
	"github.com/projectdiscovery/goflags"
	"os"
	"sync"
)

var (
	wg        sync.WaitGroup
	myOptions = &opt.Options{}
)

const (
	VERSION = "1.0.0"
)

func ReadFlags() *goflags.FlagSet {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Parameter Fuzzer - Extract and Analyze Parameters")

	createGroup(flagSet, "input", "Input",
		flagSet.StringVarP(&myOptions.InputUrls, "url", "u", "", "Input [Filename | URL]"),
		flagSet.StringVarP(&myOptions.InputDIR, "directory", "dir", "", "Stored requests/responses files directory path (offline)"),
		flagSet.StringVarP(&myOptions.InputHttpRequest, "request", "r", "", "File containing the raw http request"),
	)

	createGroup(flagSet, "rate-limit", "Rate-Limit",
		flagSet.IntVarP(&myOptions.Thread, "thread", "t", 1, "Number of Threads [Number]"),
		flagSet.IntVarP(&myOptions.Delay, "delay", "rd", 0, "Request delay between each request in seconds"),
	)

	createGroup(flagSet, "configs", "Configurations",
		flagSet.BoolVarP(&myOptions.CrawlMode, "crawl", "c", false, "Crawl pages to extract their parameters"),
		flagSet.IntVarP(&myOptions.MaxDepth, "depth", "d", 2, "Maximum depth to crawl"),
		flagSet.DurationVarP(&myOptions.CrawlDuration, "crawl-duration", "ct", 0, "Maximum duration to crawl the target"),
		flagSet.BoolVarP(&myOptions.Headless, "headless", "hl", false, "Discover parameters with headless browser"),
		flagSet.VarP(&myOptions.CustomHeaders, "header", "H", "Header `\"Name: Value\"`, separated by colon. Multiple -H flags are accepted."),
		flagSet.StringVarP(&myOptions.RequestHttpMethod, "method", "X", "GET", "HTTP method to use"),
		flagSet.StringVarP(&myOptions.RequestBody, "body", "b", "", "POST data"),
		flagSet.StringVarP(&myOptions.ProxyUrl, "proxy", "x", "", "Proxy URL (SOCKS5 or HTTP). For example: http://127.0.0.1:8080 or socks5://127.0.0.1:8080"),
	)

	createGroup(flagSet, "extraction", "Extraction Options",
		flagSet.BoolVarP(&myOptions.ExtractJS, "javascript", "js", true, "Extract parameters from JavaScript"),
		flagSet.BoolVarP(&myOptions.ExtractHTML, "html", "html", true, "Extract parameters from HTML elements"),
		flagSet.BoolVarP(&myOptions.ExtractForms, "forms", "f", true, "Extract parameters from HTML forms"),
		flagSet.BoolVarP(&myOptions.ExtractComments, "comments", "cm", true, "Extract potential parameters from HTML/JS comments"),
		flagSet.BoolVarP(&myOptions.ExtractJSON, "json", "j", true, "Extract parameters from JSON data"),
		flagSet.BoolVarP(&myOptions.ExtractPaths, "paths", "p", true, "Extract parameters from URL paths"),
	)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&myOptions.OutputFile, "output", "o", "parameters.txt", "File to write output to"),
		flagSet.BoolVarP(&myOptions.OutputJSON, "json-output", "jo", false, "Output results as JSON"),
		flagSet.IntVarP(&myOptions.MaxLength, "max-length", "xl", 30, "Maximum length of parameter names"),
		flagSet.IntVarP(&myOptions.MinLength, "min-length", "nl", 0, "Minimum length of parameter names"),
		flagSet.BoolVar(&myOptions.SilentMode, "silent", false, "Disables the banner and prints output to the command line."),
		flagSet.BoolVarP(&myOptions.VerboseMode, "verbose", "v", false, "Show more information about the extraction process"),
	)

	createGroup(flagSet, "update", "Update",
		flagSet.BoolVarP(&myOptions.DisableUpdateCheck, "disable-update-check", "duc", false, "Disable automatic paramFuzzer update check"),
	)
	err := flagSet.Parse()
	utils.CheckError(err)

	return flagSet
}

func main() {
	_ = ReadFlags()
	if myOptions.InputHttpRequest != "" {
		utils.ParseHttpRequest(myOptions)
	}
	err := validate.Options(myOptions)
	utils.CheckError(err)

	var channel = utils.GetInput(myOptions)
	utils.ShowBanner(VERSION, len(channel), myOptions)
	_, _ = os.Create(myOptions.OutputFile)

	for i := 0; i < myOptions.Thread; i++ {
		wg.Add(1)
		go extract.Start(channel, myOptions, &wg)
	}
	wg.Wait()

	defer utils.FinalMessage(myOptions)
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}
