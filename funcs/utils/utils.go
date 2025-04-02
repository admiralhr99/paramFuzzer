package utils

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"github.com/admiralhr99/paramFuzzer/funcs/opt"
	"github.com/admiralhr99/paramFuzzer/funcs/validate"
	"github.com/projectdiscovery/gologger"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	colorReset = "\033[0m"
	colorGreen = "\033[32m"
	colorBlue  = "\033[34m"
	colorRed   = "\033[0;31m"
)

// Known suspicious parameters categorized by vulnerability type
var (
	SuspiciousCMDi         = []string{"execute", "dir", "daemon", "cli", "log", "cmd", "download", "ip", "upload"}
	SuspiciousDebug        = []string{"test", "reset", "config", "shell", "admin", "exec", "load", "cfg", "dbg", "edit", "root", "create", "access", "disable", "alter", "make", "grant", "adm", "toggle", "execute", "clone", "delete", "enable", "rename", "debug", "modify"}
	SuspiciousFileInc      = []string{"root", "directory", "path", "style", "folder", "default-language", "url", "platform", "textdomain", "document", "template", "pg", "php_path", "doc", "type", "lang", "token", "name", "pdf", "file", "etc", "api", "app", "resource-type"}
	SuspiciousIDOR         = []string{"count", "key", "user", "id", "extended_data", "uid2", "group", "team_id", "data-id", "no", "username", "email", "account", "doc", "uuid", "profile", "number", "user_id", "edit", "report", "order"}
	SuspiciousOpenRedirect = []string{"u", "redirect_uri", "failed", "r", "referer", "return_url", "redirect_url", "prejoin_data", "continue", "redir", "return_to", "origin", "redirect_to", "next"}
	SuspiciousSQLi         = []string{"process", "string", "id", "referer", "password", "pwd", "field", "view", "sleep", "column", "log", "token", "sel", "select", "sort", "from", "search", "update", "pub_group_id", "row", "results", "role", "table", "multi_layer_map_list", "order", "filter", "params", "user", "fetch", "limit", "keyword", "email", "query", "c", "name", "where", "number", "phone_number", "delete", "report"}
	SuspiciousSSRF         = []string{"sector_identifier_uri", "request_uris", "logo_uri", "jwks_uri", "start", "path", "domain", "source", "url", "site", "view", "template", "page", "show", "val", "dest", "metadata", "out", "feed", "navigation", "image_host", "uri", "next", "continue", "host", "window", "dir", "reference", "filename", "html", "to", "return", "open", "port", "stop", "validate", "resturl", "callback", "name", "data", "ip", "redirect"}
	SuspiciousSSTI         = []string{"preview", "activity", "id", "name", "content", "view", "template", "redirect"}
	SuspiciousXSS          = []string{"path", "admin", "class", "atb", "redirect_uri", "other", "utm_source", "currency", "dir", "title", "endpoint", "return_url", "users", "cookie", "state", "callback", "militarybranch", "e", "referer", "password", "author", "body", "status", "utm_campaign", "value", "text", "search", "flaw", "vote", "pathname", "params", "user", "t", "utm_medium", "q", "email", "what", "file", "data-original", "description", "subject", "action", "u", "nickname", "color", "language_id", "auth", "samlresponse", "return", "readyfunction", "where", "tags", "cvo_sid1", "target", "format", "back", "term", "r", "id", "url", "view", "username", "sequel", "type", "city", "src", "p", "label", "ctx", "style", "html", "ad_type", "s", "issues", "query", "c", "shop", "redirect"}
	SuspiciousMassAssign   = []string{"user", "profile", "role", "settings", "data", "attributes", "post", "comment", "order", "product", "form_fields", "request"}
)

// Helper regexp patterns
var (
	// Regex for JSON keys
	RegexJSONKeys = regexp.MustCompile(`"([a-zA-Z0-9$_\.-]*?)":`)

	// Regex for XML attributes
	RegexXMLAttr = regexp.MustCompile(`<([a-zA-Z0-9$_\.-]*?)>`)

	// Regex for HTML input fields
	RegexHTMLInput     = regexp.MustCompile(`<input(.*?)>`)
	RegexHTMLInputName = regexp.MustCompile(`(?<=\sname)[\s]*\=[\s]*(\"|')(.*?)(?=(\"|'))`)
	RegexHTMLInputID   = regexp.MustCompile(`(?<=\sid)[\s]*\=[\s]*(\"|')(.*?)(?=(\"|'))`)

	// Regex for Javascript variables
	RegexJSLet   = regexp.MustCompile(`(?<=let[\s])[\s]*[a-zA-Z$_][a-zA-Z0-9$_]*[\s]*(?=(\=|;|\n|\r))`)
	RegexJSVar   = regexp.MustCompile(`(?<=var\s)[\s]*[a-zA-Z$_][a-zA-Z0-9$_]*?(?=(\s|=|,|;|\n))`)
	RegexJSConst = regexp.MustCompile(`(?<=const\s)[\s]*[a-zA-Z$_][a-zA-Z0-9$_]*?(?=(\s|=|,|;|\n))`)

	// Regex for URL parameters
	RegexURLParams = regexp.MustCompile(`(?<=\?|&)[^\=\&\n].*?(?=\=|&|\n)`)
)

// Unique returns a unique list of strings
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

// ShowBanner displays the tool banner with version information
func ShowBanner(version string, inputLength int, myOptions *opt.Options) {
	if !myOptions.SilentMode {
		var banner = "ICAgICBfX19fXyAgICAgICAgICAgICAgICAgICBfX19fXyAgICAgICAgICAgIF9fX19fICAgICAgICAgICAgICAgICAgCiAgICAvIF9fX19cX19fX19fX19fX19fX19fX18vIF9fX19cX19fX19fX19fXy8gX19fX1wgICAgICAgICAgICAgICAgIAogICAvIC9fXyAgX19fIF9fLyBfXyBfXy8gX18gXCAgXF9fXyBcX18gX18vIC8gL19fICBfX19fX19fX18gX19fX18gCiAgLyAvICAvIC8gLyAvIC8gLyAvIC8gLy8gLyAvICAgICAvIC8gLyAvIC8gLyAvIC8gLyBfXyBcLyBfXyBcLyBfXyBcCiAvIC8gIC9fLyAvIC9fLyAvXy8gL18vIC9fLyAvX19cX18vIC9fLyAvXy8gLyAvXy8gLyAvXy8gLyAvXy8gLyAvIC8gLwovXy8gICBcX18sXy9cX18sXy9cX18sX1xfXyxfL19fX19fLy9cX18sXy9cX18sXy9cX18sXy9cX19fXy9cX19fXy9fLyAvXy8="
		bannerByte, _ := base64.StdEncoding.DecodeString(banner)
		gologger.Print().Msgf("%s\n\n", strings.Replace(string(bannerByte), "1.0.0", version, 1))

		// Check Updates
		if !myOptions.DisableUpdateCheck {
			resp, err := http.Get("https://github.com/admiralhr99/paramFuzzer")
			CheckError(err)
			respByte, err := io.ReadAll(resp.Body)
			CheckError(err)
			body := string(respByte)
			re, e := regexp.Compile(`paramFuzzer\s+v(\d\.\d\.\d+)`)
			CheckError(e)

			msg := ""
			if match := re.FindStringSubmatch(body); len(match) > 1 {
				if match[1] == version {
					msg = fmt.Sprintf("the %slatest%s", colorGreen, colorReset)
				} else {
					msg = fmt.Sprintf("an %soutdated%s", colorRed, colorReset)
				}
			} else {
				msg = fmt.Sprintf("a %sversion with unknown status%s", colorBlue, colorReset)
			}
			gologger.Info().Msgf("Installed paramFuzzer is %s version", msg)
		}
		gologger.Info().Msgf("Started creating a custom parameter wordlist using %d URLs", inputLength)
		if myOptions.CrawlMode {
			gologger.Info().Msgf("Crawl mode has been enabled\n")
		}
		if myOptions.Headless {
			gologger.Info().Msgf("Headless mode has been enabled\n")
		}
	}
}

// FinalMessage displays the final results message
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

// CheckError checks for an error and terminates the program if one exists
func CheckError(e error) {
	if e != nil {
		gologger.Fatal().Msg(e.Error())
	}
}

// GetInput returns a channel of input URLs to process
func GetInput(options *opt.Options) chan string {
	var allUrls []string
	if options.InputUrls != "" {
		allUrls = Read(options.InputUrls)
		allUrls = Unique(validate.Clear(allUrls))
	} else if options.InputDIR != "" {
		allUrls = DIR(options.InputDIR)
	} else if options.InputHttpRequest != "" {
		allUrls = ParseHttpRequest(options)
	}

	channel := make(chan string, len(allUrls))
	for _, myLink := range allUrls {
		channel <- myLink
	}
	close(channel)

	return channel
}

// Read reads a file or returns a URL as a slice
func Read(input string) []string {
	if validate.IsUrl(input) {
		return []string{input}
	}
	fileByte, err := os.ReadFile(input)
	CheckError(err)
	return strings.Split(string(fileByte), "\n")
}

// DIR reads all files in a directory
func DIR(directory string) []string {
	if _, err := os.Stat(directory); os.IsNotExist(err) {
		gologger.Fatal().Msg("Directory does not exist")
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

// ParseHttpRequest parses a raw HTTP request file
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

// IsSuspiciousParameter checks if a parameter is on the suspicious parameter list
func IsSuspiciousParameter(param string) (bool, []string) {
	param = strings.ToLower(param)
	vulnTypes := []string{}

	checkList := func(list []string, vulnType string) {
		for _, suspParam := range list {
			if param == suspParam {
				vulnTypes = append(vulnTypes, vulnType)
				break
			}
		}
	}

	checkList(SuspiciousCMDi, "Command Injection")
	checkList(SuspiciousDebug, "Debug")
	checkList(SuspiciousFileInc, "File Inclusion")
	checkList(SuspiciousIDOR, "IDOR")
	checkList(SuspiciousOpenRedirect, "Open Redirect")
	checkList(SuspiciousSQLi, "SQL Injection")
	checkList(SuspiciousSSRF, "SSRF")
	checkList(SuspiciousSSTI, "SSTI")
	checkList(SuspiciousXSS, "XSS")
	checkList(SuspiciousMassAssign, "Mass Assignment")

	return len(vulnTypes) > 0, vulnTypes
}
