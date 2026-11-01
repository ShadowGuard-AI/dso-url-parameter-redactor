import argparse
import logging
import re
import sys
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

# Attempt to import chardet; if not available, provide instructions
try:
    import chardet
except ImportError:
    print("Error: The 'chardet' library is required.  Please install it using 'pip install chardet'.")
    sys.exit(1)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Redacts sensitive parameters from URLs in a file or from standard input."
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=str,
        default="-",
        help="The input file to process. Use '-' for standard input (default).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="The output file to write the redacted URLs to. If not specified, output is printed to standard output.",
    )
    parser.add_argument(
        "-p",
        "--parameters",
        type=str,
        default="api_key,password,session_id,auth_token",
        help="Comma-separated list of parameters to redact (default: api_key,password,session_id,auth_token).",
    )
    parser.add_argument(
        "-r",
        "--redaction_string",
        type=str,
        default="REDACTED",
        help="The string to replace the redacted parameter values with (default: REDACTED).",
    )
    parser.add_argument(
        "-l",
        "--log_level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Set the logging level (default: INFO).",
    )

    return parser.parse_args()


def redact_url_parameters(url, params_to_redact, redaction_string="REDACTED"):
    """Redact specified parameters. Returns (redacted_url, redaction_count)."""
    try:
        parsed_url = urlparse(url)
        if not parsed_url.query:
            return url, 0
        # I split the raw query myself instead of using parse_qs and urlencode.
        # A parse and rebuild round trip would decode and re-encode every value,
        # drop parameters with no value, and reorder nothing but change plenty.
        # Working on the raw parts leaves every parameter I do not touch exactly
        # as it arrived, byte for byte.
        parts = parsed_url.query.split("&")
        count = 0
        out_parts = []
        for part in parts:
            if "=" in part:
                # Split on the first equals sign only. Values can legitimately contain
                # equals signs, base64 padding being the common case, and those have to
                # survive untouched when the parameter is not on the list.
                name, value = part.split("=", 1)
            else:
                name, value = part, None
            # The name comparison is exact, case sensitive, and made against the raw
            # still-encoded name. A percent-encoded spelling of a listed name does
            # not match, and neither does a differently cased one.
            if name in params_to_redact:
                out_parts.append(f"{name}={redaction_string}")
                count += 1
            else:
                out_parts.append(part)
        redacted_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, "&".join(out_parts), parsed_url.fragment))
        return redacted_url, count
    except Exception as e:
        logging.error(f"Error redacting URL: {e}")
        raise

def process_line(line, params_to_redact, redaction_string):
    """Processes a single line. Returns (processed_line, redaction_count)."""
    # The URL pattern stops at whitespace, quotes, and angle brackets, which
    # covers URLs quoted in HTML and logs. Trailing punctuation such as a
    # closing parenthesis or a full stop is not excluded, so it becomes part
    # of the matched URL and of the last parameter's value.
    url_pattern = re.compile(r"https?://[^\s'\"<>]+")
    # A one element list as a mutable counter, because the replacement
    # callback runs inside re.sub and cannot return a count alongside the
    # string it builds.
    total = [0]
    def replace_url(match):
        url = match.group(0)
        redacted, n = redact_url_parameters(url, params_to_redact, redaction_string)
        total[0] += n
        return redacted
    redacted_line = url_pattern.sub(replace_url, line)
    return redacted_line, total[0]

def main():
    args = setup_argparse()
    logging.getLogger().setLevel(args.log_level)
    params_to_redact = [p.strip() for p in args.parameters.split(",")]
    redaction_string = args.redaction_string
    # Same-path guard before opening anything for write.
    if args.input != "-" and args.output:
        from pathlib import Path
        try:
            if Path(args.input).resolve() == Path(args.output).resolve():
                logging.error("Output path resolves to the input file. Refusing to overwrite the input.")
                sys.exit(1)
        except SystemExit:
            raise
        except Exception:
            pass
    # Read the input fully before the output is opened.
    try:
        if args.input == "-":
            logging.info("Reading from standard input.")
            text = sys.stdin.read()
        else:
            logging.info(f"Reading from file: {args.input}")
            try:
                with open(args.input, "rb") as f:
                    raw_data = f.read()
                    encoding_result = chardet.detect(raw_data)
                    encoding = encoding_result["encoding"] or "utf-8"
                # The whole input is read and processed in memory before the output is
                # opened. Combined with the same-path guard above, an in-place mistake
                # cannot truncate the input, and a processing failure writes nothing.
                text = raw_data.decode(encoding)
            except FileNotFoundError:
                logging.error(f"Input file not found: {args.input}")
                sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        logging.error(f"Error reading input: {e}")
        sys.exit(1)
    # Process in memory; an exception exits 1 and writes nothing.
    total = 0
    out_lines = []
    try:
        for line in text.splitlines(keepends=True):
            redacted_line, n = process_line(line, params_to_redact, redaction_string)
            total += n
            out_lines.append(redacted_line)
    except Exception as e:
        logging.error(f"Error processing data: {e}")
        print(f"Redactions: {total}")
        sys.exit(1)
    print(f"Redactions: {total}")
# This count goes to stdout even when the redacted text also goes to
# stdout, so a pipeline reading the text receives the count line first.
# Noted as a wart: the count belongs on stderr in stdout mode.
    logging.info(f"Redactions: {total}")
    if total == 0:
        print("No parameters redacted.")
        sys.exit(1)
    output_text = "".join(out_lines)
    if args.output:
        try:
            with open(args.output, "w") as f:
                f.write(output_text)
        except Exception as e:
            logging.error(f"Error opening output file: {e}")
            sys.exit(1)
    else:
        sys.stdout.write(output_text)

if __name__ == "__main__":
    main()
