package main

import (
	"github.com/admiralhr99/paramFuzzer/funcs/opt"
	"github.com/admiralhr99/paramFuzzer/funcs/run"
	"github.com/admiralhr99/paramFuzzer/funcs/utils"
	"github.com/admiralhr99/paramFuzzer/funcs/validate"
	"github.com/projectdiscovery/goflags"
	"sync"
)

var (
	wg        sync.WaitGroup
	myOptions = &opt.Options{}
)

const (
	VERSION = "2.2.0"
)

func ReadFlags() *goflags.FlagSet {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Find All Parameters")

	// In the input group description
	createGroup(flagSet, "input", "Input",
		flagSet.StringVarP(&myOptions.InputUrls, "url", "u", "", "Input [Filename | URL with http/https] (stdin can also be used for input)"),
		flagSet.StringVarP(&myOptions.InputDIR, "directory", "dir", "", "Stored requests/responses files directory path (offline)"),
		flagSet.StringVarP(&myOptions.InputHttpRequest, "request", "r", "", "File containing the raw http request"),
	)

	createGroup(flagSet, "rate-limit", "Rate-Limit",
		flagSet.IntVarP(&myOptions.Thread, "thread", "t", 1, "Number of Threads [Number]"),
		flagSet.IntVarP(&myOptions.Delay, "delay", "rd", 0, "Request delay between each request in seconds"),
	)

	createGroup(flagSet, "configs", "Configurations",
		flagSet.BoolVarP(&myOptions.CrawlMode, "crawl", "c", false, "Crawl pages to extract their parameters"),
		flagSet.IntVarP(&myOptions.MaxDepth, "depth", "d", 2, "maximum depth to crawl"),
		flagSet.DurationVarP(&myOptions.CrawlDuration, "crawl-duration", "ct", 0, "maximum duration to crawl the target"),
		flagSet.BoolVarP(&myOptions.Headless, "headless", "hl", false, "Discover parameters with headless browser"),
		flagSet.VarP(&myOptions.CustomHeaders, "header", "H", "Header `\"Name: Value\"`, separated by colon. Multiple -H flags are accepted."),
		flagSet.StringVarP(&myOptions.RequestHttpMethod, "method", "X", "GET", "HTTP method to use"),
		flagSet.StringVarP(&myOptions.RequestBody, "body", "b", "", "POST data"),
		flagSet.StringVarP(&myOptions.ProxyUrl, "proxy", "x", "", "Proxy URL (SOCKS5 or HTTP). For example: http://127.0.0.1:8080 or socks5://127.0.0.1:8080"),
	)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&myOptions.OutputFile, "output", "o", "", "File to write output to (default: console output)"),
		flagSet.IntVarP(&myOptions.MaxLength, "max-length", "xl", 30, "Maximum length of words"),
		flagSet.IntVarP(&myOptions.MinLength, "min-length", "nl", 0, "Minimum length of words"),
		flagSet.BoolVar(&myOptions.SilentMode, "silent", false, "Disables the banner and verbose output"),
		flagSet.BoolVar(&myOptions.ReportSusParams, "sus", false, "Identify and report suspicious parameters"),
		flagSet.StringVar(&myOptions.OutputSortOrder, "sort", "alpha", "Sort parameters: alpha, length, or none"),
		flagSet.StringVar(&myOptions.ExportFormat, "format", "txt", "Output format: txt, csv, or json"),
		flagSet.BoolVar(&myOptions.IncludeOrigin, "include-origin", false, "Include parameter origin in output"),
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

	// Get input channel (streaming)
	channel := utils.GetInput(myOptions)

	// Get estimated count for banner (might be -1 for unknown)
	inputCount := utils.GetInputEstimate(myOptions)
	utils.ShowBanner(VERSION, inputCount, myOptions)

	// REMOVED: No longer automatically create output file
	// Only create file if user explicitly set -o flag
	// _, _ = os.Create(myOptions.OutputFile)

	// Start worker goroutines
	for i := 0; i < myOptions.Thread; i++ {
		wg.Add(1)
		go run.Start(channel, myOptions, &wg)
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
