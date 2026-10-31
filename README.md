![Banner](banner.png)

# dso-url-parameter-redactor
A command-line tool that analyzes web server access logs and redacts sensitive parameters (e.g., API keys, passwords, session IDs) from URLs, replacing them with placeholders to protect user privacy and prevent data leakage in logs. - Focused on Tools for sanitizing and obfuscating sensitive data within text files and structured data formats

## Install
`git clone https://github.com/ShadowStrikeHQ/dso-url-parameter-redactor`

## Usage
`python3 main.py input.log [-o output.log] [-p api_key,password,session_id,auth_token] [-r REDACTED]`

Notes on behaviour:
- Whole URLs in each line are passed to the redactor, so a sensitive parameter is redacted in first, second, and repeated positions. The parameter name and the URL shape stay in place; only the value is replaced.
- If the resolved output path is the input file (same path, a ./ alias, or a symlink to it), the run refuses at exit 1. The input is read fully before the output is opened.
- Every run prints a redaction count. If nothing is redacted, the run prints a plain no parameters redacted line and exits 1. An error during processing also exits 1.
- This tool does not use the faker library; it is not a dependency.

## Parameters
- `-h`: Show help message and exit
- `-o`: The output file to write the redacted URLs to. If not specified, output is printed to standard output.
- `-p`: No description provided
- `-r`: No description provided
- `-l`: No description provided

## License
Copyright (c) ShadowStrikeHQ
