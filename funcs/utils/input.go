package utils

import (
	"bufio"
	"github.com/admiralhr99/paramFuzzer/funcs/opt"
	"github.com/admiralhr99/paramFuzzer/funcs/validate"
	"github.com/projectdiscovery/gologger"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// MaxLineLength sets the maximum line length for scanner
	MaxLineLength = 1024 * 1024 // 1MB per line
	// ChannelBufferSize sets the buffered channel size
	ChannelBufferSize = 1000
)

func GetInput(options *opt.Options) chan string {
	// Check if there is input from stdin
	info, err := os.Stdin.Stat()
	stdinHasData := (err == nil && (info.Mode()&os.ModeCharDevice) == 0)

	// Create a buffered channel for streaming
	channel := make(chan string, ChannelBufferSize)

	// Start a goroutine to populate the channel
	go func() {
		defer close(channel)

		if options.InputUrls != "" {
			processInput(options.InputUrls, channel)
		} else if options.InputDIR != "" {
			processDirectory(options.InputDIR, channel)
		} else if options.InputHttpRequest != "" {
			urls := ParseHttpRequest(options)
			for _, url := range urls {
				url = strings.TrimSpace(url)
				if url != "" {
					channel <- url
				}
			}
		} else if stdinHasData {
			gologger.Info().Msg("Reading from stdin...")
			processReader(os.Stdin, channel, "stdin")
		}
	}()

	return channel
}

// processInput handles single URL or file input
func processInput(input string, channel chan<- string) {
	input = strings.TrimSpace(input)

	// Check if it's a URL (must have http:// or https://)
	if validate.IsUrl(input) {
		gologger.Info().Msgf("Processing URL: %s", input)
		channel <- input
		return
	}

	// Not a URL, treat as file
	gologger.Info().Msgf("Processing file: %s", input)
	file, err := os.Open(input)
	if err != nil {
		if os.IsNotExist(err) {
			gologger.Fatal().Msgf("File '%s' does not exist", input)
		}
		gologger.Fatal().Msgf("Error opening file '%s': %v", input, err)
	}
	defer file.Close()

	processReader(file, channel, input)
}

// processReader reads from any io.Reader line by line (chunked)
func processReader(reader io.Reader, channel chan<- string, source string) {
	scanner := bufio.NewScanner(reader)

	// Increase buffer size for large lines
	buf := make([]byte, 0, MaxLineLength)
	scanner.Buffer(buf, MaxLineLength)

	lineCount := 0
	validCount := 0

	for scanner.Scan() {
		lineCount++
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		// Process the line
		if processedURL := processLine(line); processedURL != "" {
			channel <- processedURL
			validCount++
		}

		// Log progress for large files
		if lineCount%10000 == 0 {
			gologger.Info().Msgf("Processed %d lines from %s (%d valid URLs)", lineCount, source, validCount)
		}
	}

	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			gologger.Warning().Msgf("Line too long in %s (max %d bytes)", source, MaxLineLength)
		} else {
			gologger.Fatal().Msgf("Error reading from %s: %v", source, err)
		}
	}

	if lineCount > 0 {
		gologger.Info().Msgf("Finished processing %s: %d total lines, %d valid URLs", source, lineCount, validCount)
	}
}

// processDirectory processes all files in a directory
func processDirectory(directory string, channel chan<- string) {
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		gologger.Fatal().Msg("Directory does not exist")
	}

	gologger.Info().Msgf("Processing directory: %s", directory)

	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			gologger.Warning().Msgf("Error accessing %s: %v", path, err)
			return nil
		}

		if info.IsDir() {
			return nil
		}

		// For directory mode, maintain original format but with memory awareness
		if info.Size() > 100*1024*1024 { // 100MB
			gologger.Warning().Msgf("File %s is very large (%d MB)", path, info.Size()/1024/1024)
		}

		// Read file content
		dat, err := os.ReadFile(path)
		if err != nil {
			gologger.Warning().Msgf("Cannot read file %s: %v", path, err)
			return nil
		}

		// Send in the expected format for directory processing
		channel <- info.Name() + "{==MY=FILE=NAME==}" + string(dat)
		return nil
	})

	if err != nil {
		gologger.Fatal().Msgf("Error walking directory: %v", err)
	}
}

// processLine validates and filters a URL line
func processLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Only accept valid URLs or pass through as-is for file content
	if validate.IsUrl(line) {
		// Apply filtering (skip bad extensions, etc.)
		filtered := validate.Clear([]string{line})
		if len(filtered) > 0 {
			return filtered[0]
		}
	}

	// For non-URLs in files, pass through as-is
	// The calling code will determine how to handle it
	return line
}

// GetInputEstimate returns estimated count for progress (optional)
func GetInputEstimate(options *opt.Options) int {
	if options.InputUrls != "" {
		// Quick check if it's a single URL
		if validate.IsUrl(strings.TrimSpace(options.InputUrls)) {
			return 1
		}
		// For files, return -1 (unknown)
		return -1
	}
	return -1 // Unknown count for streaming
}
