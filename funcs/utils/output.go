package utils

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Parameter represents a discovered parameter with metadata
type Parameter struct {
	Name    string `json:"name"`
	Origin  string `json:"origin,omitempty"`
	IsSus   bool   `json:"is_suspicious"`
	SusType string `json:"suspicious_type,omitempty"`
}

// ExportParameters exports parameters to a file in the specified format
func ExportParameters(filename string, params []Parameter, format string) error {
	if filename == "" {
		return nil
	}

	switch strings.ToLower(format) {
	case "txt":
		return exportAsTxt(filename, params)
	case "csv":
		return exportAsCsv(filename, params)
	case "json":
		return exportAsJson(filename, params)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

// exportAsTxt exports parameters as plain text
func exportAsTxt(filename string, params []Parameter) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, param := range params {
		line := param.Name

		if param.Origin != "" {
			line += fmt.Sprintf(" [origin: %s]", param.Origin)
		}

		if param.IsSus {
			line += fmt.Sprintf(" [suspicious: %s]", param.SusType)
		}

		if _, err := fmt.Fprintln(file, line); err != nil {
			return err
		}
	}

	return nil
}

// exportAsCsv exports parameters as CSV
func exportAsCsv(filename string, params []Parameter) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{"Parameter", "Origin", "Is_Suspicious", "Suspicious_Type"}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write records
	for _, param := range params {
		isSus := "false"
		if param.IsSus {
			isSus = "true"
		}

		record := []string{param.Name, param.Origin, isSus, param.SusType}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// exportAsJson exports parameters as JSON
func exportAsJson(filename string, params []Parameter) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(params)
}

// SortParameters sorts parameters according to the specified order
func SortParameters(params []Parameter, order string) []Parameter {
	switch strings.ToLower(order) {
	case "alpha":
		sort.Slice(params, func(i, j int) bool {
			return params[i].Name < params[j].Name
		})
	case "length":
		sort.Slice(params, func(i, j int) bool {
			return len(params[i].Name) < len(params[j].Name)
		})
	case "sus":
		sort.Slice(params, func(i, j int) bool {
			if params[i].IsSus && !params[j].IsSus {
				return true
			}
			if !params[i].IsSus && params[j].IsSus {
				return false
			}
			return params[i].Name < params[j].Name
		})
	}
	return params
}
