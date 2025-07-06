package utils

import (
	"bufio"
	"fmt"
	"github.com/admiralhr99/paramFuzzer/funcs/opt"
	"github.com/projectdiscovery/gologger"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
)

const (
	colorReset = "\033[0m"
	colorGreen = "\033[32m"
	colorBlue  = "\033[34m"
	colorRed   = "\033[0;31m"
)

var (
	OriginalStdout *os.File = os.Stdout
	OriginalStderr *os.File = os.Stderr
)

func Unique(strSlice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range strSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			if entry != "" {
				list = append(list, entry)
			}
		}
	}
	return list
}

// Add this to your utils.go file, replacing the existing ShowBanner function

// Updated ShowBanner function for utils.go

func ShowBanner(version string, inputLength int, myOptions *opt.Options) {
	if !myOptions.SilentMode {
		var banner = `
  _____                           ______                       
 |  __ \                         |  ____|                      
 | |__) |_ _ _ __ __ _ _ __ ___  | |__ _   _ ___________ _ __ 
 |  ___/ _' | '__/ _' | '_ ' _ \ |  __| | | |_  /_  / _ \ '__|
 | |  | (_| | | | (_| | | | | | || |  | |_| |/ / / /  __/ |   
 |_|   \__,_|_|  \__,_|_| |_| |_||_|   \__,_/___/___\___|_|   
                                                              
        by @admiralhr99                             v` + version

		gologger.Print().Msgf("%s\n", banner)

		// Show output mode
		if myOptions.OutputFile != "" {
			gologger.Info().Msgf("Output will be saved to: %s", myOptions.OutputFile)
		} else {
			gologger.Info().Msg("Output mode: Console (use -o filename.txt to save to file)")
		}

		// Handle different input scenarios
		if inputLength == 1 {
			gologger.Info().Msg("Started processing single URL")
		} else if inputLength == -1 {
			gologger.Info().Msg("Started processing input (streaming mode)")
		} else {
			gologger.Info().Msgf("Started processing %d URLs", inputLength)
		}

		if myOptions.CrawlMode {
			gologger.Info().Msg("Crawl mode enabled")
		}
		if myOptions.Headless {
			gologger.Info().Msg("Headless browser mode enabled")
		}
		if myOptions.ProxyUrl != "" {
			gologger.Info().Msgf("Using proxy: %s", myOptions.ProxyUrl)
		}
		if myOptions.ReportSusParams {
			gologger.Info().Msg("Suspicious parameter detection enabled")
		}

		gologger.Print().Msg("") // Empty line for spacing

		// Show header for parameters if console output
		if myOptions.OutputFile == "" {
			gologger.Info().Msg("Parameters found:")
			gologger.Print().Msg("") // Empty line
		}
	}
}

// Complete FinalMessage function for utils.go - handles console output by default

func FinalMessage(options *opt.Options) {
	// Only process file if user explicitly set -o flag
	if options.OutputFile != "" {
		// Check if file exists and process it
		if _, err := os.Stat(options.OutputFile); err == nil {
			dat, err := os.ReadFile(options.OutputFile)
			if err == nil && len(dat) > 0 {
				uniqData := strings.Join(Unique(strings.Split(string(dat), "\n")), "\n")
				_ = os.WriteFile(options.OutputFile, []byte(uniqData), 0644)

				if !options.SilentMode {
					paramCount := len(strings.Split(strings.TrimSpace(uniqData), "\n"))
					if strings.TrimSpace(uniqData) != "" {
						gologger.Info().Msg(fmt.Sprintf("Parameter wordlist %ssuccessfully%s generated and saved to %s%s%s [%d unique parameters]",
							colorGreen, colorReset, colorBlue, options.OutputFile, colorReset, paramCount))
					} else {
						gologger.Warning().Msg("Output file created but no parameters were found")
					}
				}
			} else {
				// File is empty or couldn't be read
				if !options.SilentMode {
					gologger.Warning().Msg("No parameters found to save to file")
				}
				// Remove empty files
				_ = os.Remove(options.OutputFile)
			}
		} else {
			// File doesn't exist
			if !options.SilentMode {
				gologger.Warning().Msg("No output file was created - no parameters found")
			}
		}
	} else {
		// Console output mode - no file processing needed
		if !options.SilentMode {
			gologger.Info().Msg(fmt.Sprintf("%sParameter discovery completed%s - results displayed above", colorGreen, colorReset))
			gologger.Info().Msg("Use -o filename.txt to save results to a file")
		}
	}
}

func CheckError(e error) {
	if e != nil {
		gologger.Fatal().Msg(e.Error())
	}
}

func Silent() {
	devNull, err := os.Open(os.DevNull)
	CheckError(err)
	os.Stdout = devNull
	os.Stderr = devNull
}

func Speak() {
	os.Stdout = OriginalStdout
	os.Stderr = OriginalStderr
}

func MyRegex(myRegex string, response string, indexes []int) []string {
	r, e := regexp.Compile(myRegex)
	CheckError(e)
	allName := r.FindAllStringSubmatch(response, -1)
	var finalResult []string
	for _, index := range indexes {
		for _, v := range allName {
			if v[index] != "" {
				finalResult = append(finalResult, v[index])
			}
		}
	}
	return finalResult
}

func ParseHttpRequest(options *opt.Options) []string {
	var allUrls []string
	file, err := os.Open(options.InputHttpRequest)
	CheckError(err)
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if strings.Contains(lines[0], "HTTP/2") {
		lines[0] = strings.Replace(lines[0], "HTTP/2", "HTTP/1.1", 1)
	}

	request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(strings.Join(lines, "\n"))))
	CheckError(err)

	host := request.Host
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	fullURL := fmt.Sprintf("%s://%s%s", scheme, host, request.URL.RequestURI())
	allUrls = append(allUrls, fullURL)

	var headers []string
	for key, values := range request.Header {
		for _, value := range values {
			headers = append(headers, fmt.Sprintf("%s: %s", key, value))
		}
	}

	var body string
	if request.Body != nil {
		bodyBytes, err := ioutil.ReadAll(request.Body)
		CheckError(err)
		body = string(bodyBytes)
		request.Body = ioutil.NopCloser(strings.NewReader(body))
	}

	options.CustomHeaders = append(options.CustomHeaders, headers...)
	options.RequestHttpMethod = request.Method
	options.RequestBody = body

	return allUrls
}
