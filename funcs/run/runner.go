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

// run/runner.go - Updated to use new output formatting

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

						// Output to console if not in silent mode
						if !myOptions.SilentMode {
							gologger.Info().Msgf("Suspicious parameter found: %s [%s]", p, vulnType)
						}
					}
				}

				allParams = append(allParams, param)

				// Write to console if silent mode is enabled
				if myOptions.SilentMode {
					if param.IsSus && myOptions.ReportSusParams {
						fmt.Printf("%s [%s]\n", p, param.SusType)
					} else {
						fmt.Println(p)
					}
				}
			}
		}
	}

	// Sort parameters
	allParams = utils.SortParameters(allParams, myOptions.OutputSortOrder)

	// Export parameters to file
	if myOptions.OutputFile != "parameters.txt" || !myOptions.SilentMode {
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
	}

	// Print summary at the end
	if !myOptions.SilentMode {
		totalSus := 0
		for _, param := range allParams {
			if param.IsSus {
				totalSus++
			}
		}

		gologger.Info().Msgf("Found %d total parameters", len(allParams))
		if myOptions.ReportSusParams {
			gologger.Info().Msgf("Found %d suspicious parameters (%.1f%%)", totalSus, float64(totalSus)/float64(len(allParams))*100)
		}
	}
}
