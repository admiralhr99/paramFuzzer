package validate

import (
	"net/url"
	"strings"
)

func Clear(links []string) []string {
	badExtensions := []string{
		".css", ".jpg", ".jpeg", ".png", ".svg", ".img", ".gif", ".exe", ".mp4", ".flv", ".pdf", ".doc", ".ogv", ".webm", ".wmv",
		".webp", ".mov", ".mp3", ".m4a", ".m4p", ".ppt", ".pptx", ".scss", ".tif", ".tiff", ".ttf", ".otf", ".woff", ".woff2", ".bmp",
		".ico", ".eot", ".htc", ".swf", ".rtf", ".image", ".rf"}
	var result []string

	for _, link := range links {
		isGoodUrl := true
		u, _ := url.Parse(link)

		for _, ext := range badExtensions {
			if strings.HasSuffix(strings.ToLower(u.Path), ext) {
				isGoodUrl = false
			}
		}

		if !IsUrl(link) {
			isGoodUrl = false
		}

		if isGoodUrl {
			result = append(result, link)
		}
	}
	return result
}

// IsUrl checks if a string is a valid URL with scheme (http:// or https://)
func IsUrl(str string) bool {
	str = strings.TrimSpace(str)
	if str == "" {
		return false
	}

	// Must start with http:// or https://
	if !strings.HasPrefix(strings.ToLower(str), "http://") && !strings.HasPrefix(strings.ToLower(str), "https://") {
		return false
	}

	// Try to parse the URL
	u, err := url.Parse(str)
	if err != nil {
		return false
	}

	// Must have both scheme and host
	return u.Scheme != "" && u.Host != ""
}
