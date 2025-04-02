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

// Replace the ShowBanner function in funcs/utils/utils.go
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

		gologger.Print().Msgf("%s\n\n", banner)
		gologger.Info().Msgf("Started creating a custom parameter wordlist using %d URLs", inputLength)

		if myOptions.CrawlMode {
			gologger.Info().Msgf("Crawl mode has been enabled\n")
		}
	}
}

func FinalMessage(options *opt.Options) {
	dat, _ := os.ReadFile(options.OutputFile)
	uniqData := strings.Join(Unique(strings.Split(string(dat), "\n")), "\n")
	_ = os.WriteFile(options.OutputFile, []byte(uniqData), 0644)

	if !options.SilentMode {
		if len(string(dat)) != 0 {
			gologger.Info().Msg(fmt.Sprintf("Parameter wordlist %ssuccessfully%s generated and saved to %s%s%s [%d unique parameters]",
				colorGreen, colorReset, colorBlue, options.OutputFile, colorReset, len(strings.Split(uniqData, "\n"))))
		} else {
			gologger.Error().Msg("I'm sorry, but I couldn't find any parameters :(")
		}
	}
	if len(string(dat)) == 0 {
		_ = os.Remove(options.OutputFile)
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
