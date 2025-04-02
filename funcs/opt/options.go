// opt/options.go - Enhanced options

package opt

import (
	"github.com/projectdiscovery/goflags"
	_ "strings"
	"time"
)

type Options struct {
	InputUrls          string
	InputDIR           string
	Thread             int
	Delay              int
	CrawlMode          bool
	MaxDepth           int
	CrawlDuration      time.Duration
	Headless           bool
	CustomHeaders      goflags.StringSlice
	OutputFile         string
	MaxLength          int
	MinLength          int
	DisableUpdateCheck bool
	RequestHttpMethod  string
	RequestBody        string
	InputHttpRequest   string
	ProxyUrl           string
	SilentMode         bool
	ReportSusParams    bool   // Added option to report suspicious parameters
	OutputSortOrder    string // Added option for custom sort order
	ExportFormat       string // Added option for export format (txt, csv, json)
	IncludeOrigin      bool   // Added option to include parameter origin in output
}
