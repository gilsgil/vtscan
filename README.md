# VirusTotal Scan Tool

This tool is a simple command-line application written in Go that queries the VirusTotal Domain Report API and extracts either subdomains or undetected URLs based on the provided mode. It also supports API key chaining with up to three keys in case of quota errors.

## Features

- **Query VirusTotal**: Send a request to the VirusTotal Domain Report API.
- **Extract Data**: Choose between extracting subdomains (`domains` mode) or undetected URLs (`urls` mode).
- **API Key Chaining**: Automatically switch between primary, secondary, and tertiary API keys if quota limits are exceeded.
- **Unique Results**: Outputs only unique lines from the extracted results.
- **Command-line Flags**: Supports `-d` for domain, `-k` for API key, and `-m` for mode.

## Requirements

- Go 1.16 or later

## Installation

Yes, you can install this tool using `go install`. To do so, run the following command:

```bash
go install github.com/gilsgil/vtscan@latest
