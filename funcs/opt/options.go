package opt

import (
	"github.com/projectdiscovery/goflags"
	"time"
)

type Options struct {
	// Input options
	InputUrls        string
	InputDIR         string
	InputHttpRequest string

	// Processing options
	Thread        int
	Delay         int
	CrawlMode     bool
	MaxDepth      int
	CrawlDuration time.Duration
	Headless      bool
	CustomHeaders goflags.StringSlice

	// HTTP Request options
	RequestHttpMethod string
	RequestBody       string
	ProxyUrl          string

	// Extraction options
	ExtractJS       bool
	ExtractHTML     bool
	ExtractForms    bool
	ExtractComments bool
	ExtractJSON     bool
	ExtractPaths    bool

	// Output options
	OutputFile           string
	OutputJSON           bool
	MaxLength            int
	MinLength            int
	SilentMode           bool
	VerboseMode          bool
	DisableUpdateCheck   bool
	ReportSuspiciousOnly bool
}
