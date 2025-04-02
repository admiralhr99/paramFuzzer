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
	"os"
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

	// Create files for normal and suspicious parameters if requested
	var normalFile, susFile *os.File
	var err error

	if myOptions.ReportSusParams && myOptions.OutputFile != "parameters.txt" {
		susFileName := strings.TrimSuffix(myOptions.OutputFile, ".txt") + "_suspicious.txt"
		susFile, err = os.Create(susFileName)
		if err != nil {
			gologger.Warning().Msgf("Could not create suspicious parameters file: %s", err)
		} else {
			defer susFile.Close()
		}
	}

	if myOptions.OutputFile != "parameters.txt" || !myOptions.SilentMode {
		normalFile, err = os.Create(myOptions.OutputFile)
		utils.CheckError(err)
		defer normalFile.Close()
	}

	// Process parameters
	allParams := make(map[string]bool)
	allSusParams := make(map[string]string)

	for v := range channel {
		foundParams := utils.Unique(Do(v, myOptions))

		for _, p := range foundParams {
			if len(p) <= myOptions.MaxLength && len(p) >= myOptions.MinLength {
				allParams[p] = true

				// Write to console if silent mode is enabled
				if myOptions.SilentMode {
					fmt.Println(p)
				}

				// Write to normal file
				if normalFile != nil {
					_, err = fmt.Fprintln(normalFile, p)
					utils.CheckError(err)
				}

				// Check if parameter is suspicious
				if myOptions.ReportSusParams {
					if isSus, vulnType := parameters.IsSusParameter(p); isSus {
						allSusParams[p] = vulnType

						// Write to suspicious parameters file if enabled
						if susFile != nil {
							_, err = fmt.Fprintf(susFile, "%s [%s]\n", p, vulnType)
							utils.CheckError(err)
						}

						// Output to console if not in silent mode
						if !myOptions.SilentMode {
							gologger.Info().Msgf("Suspicious parameter found: %s [%s]", p, vulnType)
						}
					}
				}
			}
		}
	}

	// Print summary at the end
	if !myOptions.SilentMode && myOptions.ReportSusParams && len(allSusParams) > 0 {
		gologger.Info().Msgf("Found %d suspicious parameters out of %d total parameters", len(allSusParams), len(allParams))
	}
}
