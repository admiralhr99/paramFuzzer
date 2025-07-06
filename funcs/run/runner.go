package run

import (
	"fmt"
	"github.com/admiralhr99/paramFuzzer/funcs/active"
	"github.com/admiralhr99/paramFuzzer/funcs/opt"
	"github.com/admiralhr99/paramFuzzer/funcs/parameters"
	"github.com/admiralhr99/paramFuzzer/funcs/utils"
	"github.com/admiralhr99/paramFuzzer/funcs/validate"
	"github.com/projectdiscovery/gologger"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

func Do(inp string, myOptions *opt.Options) []string {
	var params []string
	if validate.IsUrl(inp) {
		if myOptions.CrawlMode {
			params = append(params, active.SimpleCrawl(inp, myOptions)...)
		} else {
			body := ""
			httpRes := &http.Response{}
			if !myOptions.Headless {
				httpRes, body = active.SendRequest(inp, myOptions)
			} else {
				body = active.HeadlessBrowser(inp, myOptions)
			}
			cnHeader := strings.ToLower(httpRes.Header.Get("Content-Type"))

			params = append(params, parameters.Find(inp, body, cnHeader)...)
		}
	} else if len(inp) != 0 {
		cnHeader := "NOT-FOUND"
		link := ""
		fileName := strings.Split(inp, "{==MY=FILE=NAME==}")[0]
		body := strings.Split(inp, "{==MY=FILE=NAME==}")[1]
		reg, _ := regexp.Compile(`[cC][oO][nN][tT][eE][nN][tT]-[tT][yY][pP][eE]\s*:\s*([\w\-/]+)`)

		if validate.IsUrl(strings.Split(inp, "\n")[0]) {
			link = strings.Split(inp, "\n")[0]
		} else {
			link = fileName
		}

		if len(reg.FindStringSubmatch(inp)) != 0 {
			cnHeader = strings.ToLower(reg.FindStringSubmatch(inp)[1])
		}
		params = append(params, parameters.Find(link, body, cnHeader)...)
	}
	return params
}

func Start(channel chan string, myOptions *opt.Options, wg *sync.WaitGroup) {
	defer wg.Done()

	// Collection of parameters
	var allParams []utils.Parameter

	for v := range channel {
		foundParams := utils.Unique(Do(v, myOptions))

		for _, p := range foundParams {
			if len(p) <= myOptions.MaxLength && len(p) >= myOptions.MinLength {
				param := utils.Parameter{
					Name: p,
				}

				// Add origin if requested
				if myOptions.IncludeOrigin {
					param.Origin = v // Use the input as origin
				}

				// Check if parameter is suspicious
				if myOptions.ReportSusParams {
					if isSus, vulnType := parameters.IsSusParameter(p); isSus {
						param.IsSus = true
						param.SusType = vulnType
					}
				}

				allParams = append(allParams, param)

				// Output to console based on silent mode and output file settings
				shouldOutputToConsole := true

				// If silent mode AND output file is specified, don't output to console
				if myOptions.SilentMode && myOptions.OutputFile != "" {
					shouldOutputToConsole = false
				}

				if shouldOutputToConsole {
					outputToConsole(param, myOptions)
				}
			}
		}
	}

	// Sort parameters
	allParams = utils.SortParameters(allParams, myOptions.OutputSortOrder)

	// Only write to file if user explicitly set -o flag
	if myOptions.OutputFile != "" {
		err := utils.ExportParameters(myOptions.OutputFile, allParams, myOptions.ExportFormat)
		utils.CheckError(err)

		// If we're reporting suspicious parameters, create a separate output file
		if myOptions.ReportSusParams {
			var susParams []utils.Parameter
			for _, param := range allParams {
				if param.IsSus {
					susParams = append(susParams, param)
				}
			}

			if len(susParams) > 0 {
				susFileName := strings.TrimSuffix(myOptions.OutputFile, "."+myOptions.ExportFormat) + "_suspicious." + myOptions.ExportFormat
				err = utils.ExportParameters(susFileName, susParams, myOptions.ExportFormat)
				utils.CheckError(err)
			}
		}

		// Let user know file was created
		if !myOptions.SilentMode {
			gologger.Info().Msgf("Parameters saved to file: %s", myOptions.OutputFile)
		}
	}

	// Print summary at the end if not silent
	if !myOptions.SilentMode {
		totalSus := 0
		for _, param := range allParams {
			if param.IsSus {
				totalSus++
			}
		}

		gologger.Info().Msgf("Found %d total parameters", len(allParams))
		if myOptions.ReportSusParams && totalSus > 0 {
			gologger.Info().Msgf("Found %d suspicious parameters (%.1f%%)", totalSus, float64(totalSus)/float64(len(allParams))*100)
		}
	}
}

// outputToConsole handles console output for parameters
func outputToConsole(param utils.Parameter, options *opt.Options) {
	if options.SilentMode {
		// Silent mode: just print parameter names, no extra info
		if param.IsSus && options.ReportSusParams {
			fmt.Printf("%s [%s]\n", param.Name, param.SusType)
		} else {
			fmt.Println(param.Name)
		}
	} else {
		// Normal mode: can include more info
		output := param.Name

		if param.Origin != "" && options.IncludeOrigin {
			output += fmt.Sprintf(" [origin: %s]", param.Origin)
		}

		if param.IsSus && options.ReportSusParams {
			output += fmt.Sprintf(" [suspicious: %s]", param.SusType)
		}

		fmt.Println(output)
	}
}
