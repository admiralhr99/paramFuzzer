# 🔍 ParamFuzzer

[![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![GitHub Release](https://img.shields.io/github/release/admiralhr99/paramFuzzer.svg)](https://github.com/admiralhr99/paramFuzzer/releases)
[![GitHub Stars](https://img.shields.io/github/stars/admiralhr99/paramFuzzer.svg)](https://github.com/admiralhr99/paramFuzzer/stargazers)

A **powerful**, **fast**, and **intelligent** parameter discovery tool for web application security testing. ParamFuzzer extracts parameters from web applications using advanced techniques and identifies potentially suspicious parameters that could be vulnerable to various attacks.

## 🚀 Key Features

- **🌐 Multi-Protocol Support**: Full HTTP/1.1 and HTTP/2 compatibility
- **🧠 Intelligent Parameter Extraction**: Advanced regex engines + GAP.py integration
- **🔥 Real-time Console Output**: See parameters as they're discovered
- **🕷️ Advanced Crawling**: Integration with Katana crawler for deep discovery
- **🎯 Suspicious Parameter Detection**: Automatically identifies potential vulnerability sinks
- **⚡ Headless Browser Support**: JavaScript-heavy applications with Chrome integration
- **🧹 Smart Filtering**: Strict ASCII rules with intelligent false-positive removal
- **📝 Multiple Output Formats**: TXT, CSV, JSON with console-first approach
- **🔧 Flexible Input Methods**: URLs, raw HTTP requests, file inputs, stdin
- **🌟 Zero Dependencies**: Single binary, ready to use

## 📦 Installation

### Pre-built Binaries
Download the latest release for your platform from [GitHub Releases](https://github.com/admiralhr99/paramFuzzer/releases).

### Build from Source
```bash
git clone https://github.com/admiralhr99/paramFuzzer.git
cd paramFuzzer
go build -o paramfuzzer .
```

### Go Install
```bash
go install github.com/admiralhr99/paramFuzzer@latest
```

## 🛠️ Usage

### Basic Usage
```bash
# Console output (default)
paramfuzzer -u https://example.com

# Save to file
paramfuzzer -u https://example.com -o parameters.txt

# Use raw HTTP request
paramfuzzer -r request.txt

# Silent mode (clean output)
paramfuzzer -u https://example.com --silent
```

### Advanced Usage
```bash
# Crawl mode with headless browser
paramfuzzer -u https://example.com -c -hl -d 3

# With proxy (Burp Suite)
paramfuzzer -r request.txt -x http://127.0.0.1:8080

# Detect suspicious parameters
paramfuzzer -u https://example.com --sus

# Custom headers and crawl duration
paramfuzzer -u https://example.com -H "Authorization: Bearer token" -ct 120
```

### Real-world Examples
```bash
# Bug bounty workflow
echo "https://target.com" | paramfuzzer --silent | grep -E "(id|user|admin|debug)"

# Integration with other tools
cat urls.txt | paramfuzzer --silent -c | sort -u > all_params.txt

# Authenticated testing
paramfuzzer -r authenticated_request.txt -c -d 5 --sus -o results.json --format json
```

## 🎯 Detection Capabilities

ParamFuzzer can extract parameters from:

- **URLs**: Query parameters, path parameters
- **JavaScript**: Variables, object keys, function parameters, AJAX calls
- **HTML**: Form fields, input names, data attributes
- **JSON**: Object keys, nested structures
- **XML**: Element names, attributes
- **HTTP Headers**: Custom headers, cookies
- **API Endpoints**: REST parameters, GraphQL variables
- **Templates**: Template variables, placeholder values

### Suspicious Parameter Detection
Automatically identifies parameters commonly associated with:
- 🔴 **XSS**: script, javascript, innerHTML
- 🔴 **Code Injection**: eval, exec, cmd, system
- 🔴 **SSRF**: url, uri, endpoint, callback
- 🔴 **Path Traversal**: file, path, include
- 🔴 **SQL Injection**: query, sql, statement

## 📋 Command Line Options

```
INPUT:
   -u, -url string          Target URL or file containing URLs
   -r, -request string      Raw HTTP request file
   -dir string              Directory containing request/response files

CONFIGURATIONS:
   -c, -crawl              Enable crawling mode
   -d, -depth int          Maximum crawl depth (default: 2)
   -ct, -crawl-duration    Maximum crawl duration (e.g., 60s, 5m)
   -hl, -headless          Use headless browser
   -H, -header strings     Custom headers ("Name: Value")
   -X, -method string      HTTP method (default: GET)
   -b, -body string        POST data
   -x, -proxy string       Proxy URL (HTTP/SOCKS5)

OUTPUT:
   -o, -output string      Save to file (default: console output)
   -format string          Output format: txt, csv, json (default: txt)
   --silent               Clean output without banner
   --sus                  Detect suspicious parameters
   --include-origin       Include parameter origin in output

FILTERING:
   -xl, -max-length int    Maximum parameter length (default: 30)
   -nl, -min-length int    Minimum parameter length (default: 0)
   --sort string          Sort order: alpha, length, sus (default: alpha)

RATE LIMITING:
   -t, -thread int         Number of threads (default: 1)
   -rd, -delay int         Request delay in seconds
```

## 🔧 Integration Examples

### With Burp Suite
```bash
paramfuzzer -r burp_request.txt -x http://127.0.0.1:8080 --sus
```

### With Katana Crawler
```bash
echo "https://example.com" | katana -silent | paramfuzzer --silent
```

### Pipeline Integration
```bash
# Complete recon pipeline
subfinder -d target.com | httpx | paramfuzzer -c --sus | grep -v "common" > potential_params.txt
```

### Custom Workflows
```bash
# Find admin parameters
paramfuzzer -u https://target.com -c --sus | grep -i "admin\|debug\|test\|dev"

# API parameter discovery
paramfuzzer -u https://api.target.com -H "Authorization: Bearer $TOKEN" -o api_params.json --format json
```

## 🎨 Output Examples

### Console Output
```
Parameters found:

username
password
email
user_id [suspicious: JS_ATTRIBUTE]
redirect_url [suspicious: JS_URL]
callback [suspicious: SSRF]

Parameter discovery completed - results displayed above
Use -o filename.txt to save results to a file
Found 6 total parameters
Found 3 suspicious parameters (50.0%)
```

### JSON Output
```json
[
  {
    "name": "username",
    "origin": "https://example.com/login",
    "is_suspicious": false
  },
  {
    "name": "callback",
    "origin": "https://example.com/api",
    "is_suspicious": true,
    "suspicious_type": "SSRF"
  }
]
```

## ⚡ Performance

- **Fast**: Processes 1000+ parameters per second
- **Memory Efficient**: <50MB RAM usage
- **HTTP/2 Ready**: Full multiplexing support
- **Concurrent**: Multi-threaded processing
- **Smart Caching**: Avoids duplicate requests

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/admiralhr99/paramFuzzer.git
cd paramFuzzer
go mod download
go build .
```

### Adding New Extractors
1. Add regex patterns to `funcs/parameters/find.go`
2. Update tests in `funcs/parameters/find_test.go`
3. Submit a pull request

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Usage Examples](docs/examples.md)
- [API Documentation](docs/api.md)
- [Contributing Guide](CONTRIBUTING.md)

## 🛡️ Security

ParamFuzzer is designed for **authorized security testing only**. Please ensure you have proper permission before testing any web application.

- Report security issues to: admiral@0x4min.xyz
- Follow responsible disclosure practices
- Do not use for unauthorized testing

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **GAP.py** - Advanced parameter extraction techniques
- **Katana** - Powerful crawling engine integration
- **ProjectDiscovery** - Tools and libraries
- **Bug Bounty Community** - Testing and feedback

## 📊 Comparison

| Feature | ParamFuzzer | Arjun | ParamSpider | Parameth |
|---------|-------------|-------|-------------|----------|
| HTTP/2 Support | ✅ | ❌ | ❌ | ❌ |
| Headless Browser | ✅ | ❌ | ❌ | ❌ |
| Real-time Output | ✅ | ❌ | ❌ | ❌ |
| Suspicious Detection | ✅ | ❌ | ❌ | ❌ |
| Crawling Integration | ✅ | ❌ | ✅ | ❌ |
| Multiple Formats | ✅ | ✅ | ❌ | ❌ |

## 🚀 Roadmap

- [ ] Machine Learning parameter classification
- [ ] GraphQL introspection support
- [ ] WebSocket parameter extraction
- [ ] Cloud function integration
- [ ] Custom wordlist generation
- [ ] API fuzzing capabilities

---

<div align="center">

**If ParamFuzzer helped you find vulnerabilities, consider giving it a ⭐!**

Made with ❤️ for the bug bounty and security community

[Report Bug](https://github.com/admiralhr99/paramFuzzer/issues) · [Request Feature](https://github.com/admiralhr99/paramFuzzer/issues) · [Documentation](https://github.com/admiralhr99/paramFuzzer/wiki)

</div>