package utils

import (
	"bufio"
	"github.com/admiralhr99/paramFuzzer/funcs/opt"
	"github.com/admiralhr99/paramFuzzer/funcs/validate"
	"github.com/projectdiscovery/gologger"
	"os"
	"path/filepath"
	"strings"
)

func GetInput(options *opt.Options) chan string {
	var allUrls []string

	// Check if there is input from stdin
	info, err := os.Stdin.Stat()
	stdinHasData := (err == nil && (info.Mode()&os.ModeCharDevice) == 0)

	if options.InputUrls != "" {
		allUrls = Read(options.InputUrls)
		allUrls = Unique(validate.Clear(allUrls))
	} else if options.InputDIR != "" {
		allUrls = DIR(options.InputDIR)
	} else if options.InputHttpRequest != "" {
		allUrls = ParseHttpRequest(options)
	} else if stdinHasData {
		// Read from stdin
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			url := scanner.Text()
			if url != "" {
				allUrls = append(allUrls, url)
			}
		}
		allUrls = Unique(validate.Clear(allUrls))
	}

	channel := make(chan string, len(allUrls))
	for _, myLink := range allUrls {
		channel <- myLink
	}
	close(channel)

	return channel
}

func Read(input string) []string {
	if validate.IsUrl(input) {
		return []string{input}
	}
	fileByte, err := os.ReadFile(input)
	CheckError(err)
	return strings.Split(string(fileByte), "\n")
}

func DIR(directory string) []string {
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		gologger.Fatal().Msg("Not Exist")
	}

	var result []string
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			dat, _ := os.ReadFile(path)
			result = append(result, info.Name()+"{==MY=FILE=NAME==}"+string(dat))
		}
		return err
	})
	CheckError(err)

	return result
}
