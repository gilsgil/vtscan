package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// VTResponse represents the relevant parts of the VirusTotal API response.
type VTResponse struct {
	Subdomains     []string          `json:"subdomains"`
	UndetectedUrls [][]interface{}   `json:"undetected_urls"`
}

func main() {
	// Parse command-line parameters
	domain := flag.String("d", "", "Domain to query (required)")
	apiKeyFlag := flag.String("k", "", "VirusTotal API key (optional)")
	mode := flag.String("m", "", "Mode: 'domains' or 'urls' (required)")
	flag.Parse()

	if *domain == "" {
		fmt.Println("Error: Domain (-d) is required.")
		os.Exit(1)
	}
	if *mode == "" {
		fmt.Println("Error: Mode (-m) is required and must be either 'domains' or 'urls'.")
		os.Exit(1)
	}
	if *mode != "domains" && *mode != "urls" {
		fmt.Println("Error: Mode (-m) must be either 'domains' or 'urls'.")
		os.Exit(1)
	}

	// Prepare the list of API keys.
	var keys []string
	if *apiKeyFlag != "" {
		keys = append(keys, *apiKeyFlag)
		if key2 := os.Getenv("VT_API_KEY2"); key2 != "" {
			keys = append(keys, key2)
		}
		if key3 := os.Getenv("VT_API_KEY3"); key3 != "" {
			keys = append(keys, key3)
		}
	} else {
		primary := os.Getenv("VT_API_KEY")
		if primary == "" {
			fmt.Println("Error: No API key provided. Use -k flag or set VT_API_KEY in the environment.")
			os.Exit(1)
		}
		keys = append(keys, primary)
		if key2 := os.Getenv("VT_API_KEY2"); key2 != "" {
			keys = append(keys, key2)
		}
		if key3 := os.Getenv("VT_API_KEY3"); key3 != "" {
			keys = append(keys, key3)
		}
	}

	baseURL := "https://virustotal.com/vtapi/v2/domain/report"
	var resultBody []byte

	// Try each API key until a successful response is received.
	for _, key := range keys {
		params := url.Values{}
		params.Add("apikey", key)
		params.Add("domain", *domain)
		requestURL := fmt.Sprintf("%s?%s", baseURL, params.Encode())

		resp, err := http.Get(requestURL)
		if err != nil {
			fmt.Printf("Error making request with key %s: %v\n", key, err)
			continue
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			fmt.Printf("Error reading response with key %s: %v\n", key, err)
			continue
		}

		// If status is not OK, check for quota errors.
		if resp.StatusCode != http.StatusOK {
			if resp.StatusCode == 204 || strings.Contains(strings.ToLower(string(body)), "quota") {
				fmt.Printf("Quota exceeded for key %s. Trying next key if available...\n", key)
				continue
			} else {
				fmt.Printf("Unexpected error (status %d) using key %s: %s\n", resp.StatusCode, key, body)
				os.Exit(1)
			}
		}

		resultBody = body
		break
	}

	if resultBody == nil {
		fmt.Println("Error: All provided API keys have exceeded quota or failed.")
		os.Exit(1)
	}

	// Unmarshal the JSON response
	var vtResp VTResponse
	err := json.Unmarshal(resultBody, &vtResp)
	if err != nil {
		fmt.Printf("Error unmarshalling JSON: %v\n", err)
		os.Exit(1)
	}

	// Prepare a map for unique results.
	uniqueResults := make(map[string]bool)

	// Depending on the mode, extract the appropriate results.
	switch *mode {
	case "urls":
		// Extract undetected_urls. Each entry is an array; we take the first element as the URL.
		for _, entry := range vtResp.UndetectedUrls {
			if len(entry) > 0 {
				if urlStr, ok := entry[0].(string); ok {
					uniqueResults[urlStr] = true
				}
			}
		}
	case "domains":
		// Extract domains from subdomains.
		for _, d := range vtResp.Subdomains {
			uniqueResults[d] = true
		}
	}

	// Print unique lines.
	for result := range uniqueResults {
		fmt.Println(result)
	}
}
