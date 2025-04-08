import argparse
import logging
import re
import sys
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode

# Attempt to import faker; if not available, provide instructions
try:
    from faker import Faker
except ImportError:
    print("Error: The 'faker' library is required.  Please install it using 'pip install faker'.")
    sys.exit(1)

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
    """
    Redacts specified parameters from a URL, replacing their values with a placeholder.

    Args:
        url (str): The URL to redact.
        params_to_redact (list): A list of parameter names to redact.
        redaction_string (str): The string to replace the redacted parameter values with.  Defaults to "REDACTED".

    Returns:
        str: The redacted URL.  Returns the original URL if parsing fails.
    """
    try:
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        for param in params_to_redact:
            if param in query_params:
                query_params[param] = [redaction_string]  # Replace with redacted string

        redacted_query = urlencode(query_params, doseq=True)
        redacted_url = urlunparse(
            (
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                redacted_query,
                parsed_url.fragment,
            )
        )
        return redacted_url
    except Exception as e:
        logging.error(f"Error redacting URL {url}: {e}")
        return url  # Return the original URL in case of error


def process_line(line, params_to_redact, redaction_string):
    """
    Processes a single line, redacting URLs if found.

    Args:
        line (str): The line to process.
        params_to_redact (list):  A list of parameter names to redact.
        redaction_string (str): The string to replace the redacted parameter values with.

    Returns:
        str: The processed line with URLs redacted.
    """
    # Updated regex to be more robust, handling more diverse URL patterns
    url_pattern = re.compile(
        r"""
        \b
        (
            https?://              # Required scheme
            (?:
                [a-zA-Z0-9.-]+      # Domain name segments
                |                  # OR
                \[[a-fA-F0-9:]+\]  # IPv6 literal address
            )
            (?:
                :
                [0-9]+              # Optional port number
            )?
            (?:
                /                   # Path component
                [a-zA-Z0-9_@%+-]*.
                [a-zA-Z0-9_@%+-]*
            )*
            (?:                   # Start of query string (optional)
                \?
                [a-zA-Z0-9_@%&+=;-]*
                [a-zA-Z0-9_@%&+=;-]*
            )?
            (?:                   # Start of fragment (optional)
                \#
                [a-zA-Z0-9_@%&+=;-]*
                [a-zA-Z0-9_@%&+=;-]*
            )?
        )
        \b
        """,
        re.VERBOSE,
    )


    def replace_url(match):
        url = match.group(1)  # Extract the entire URL
        return redact_url_parameters(url, params_to_redact, redaction_string)

    redacted_line = url_pattern.sub(replace_url, line)
    return redacted_line


def main():
    """
    Main function to parse arguments, read input, process URLs, and write output.
    """
    args = setup_argparse()

    # Set the logging level
    logging.getLogger().setLevel(args.log_level)

    params_to_redact = [p.strip() for p in args.parameters.split(",")]
    redaction_string = args.redaction_string

    try:
        if args.input == "-":  # Read from standard input
            logging.info("Reading from standard input.")
            input_stream = sys.stdin
        else:
            logging.info(f"Reading from file: {args.input}")
            try:
                with open(args.input, "rb") as f:
                    raw_data = f.read()
                    encoding_result = chardet.detect(raw_data)
                    encoding = encoding_result["encoding"]
                input_stream = open(args.input, "r", encoding=encoding)
            except FileNotFoundError:
                logging.error(f"Input file not found: {args.input}")
                sys.exit(1)
            except Exception as e:
                logging.error(f"Error opening input file: {e}")
                sys.exit(1)

        if args.output:
            logging.info(f"Writing to file: {args.output}")
            try:
                output_stream = open(args.output, "w")
            except Exception as e:
                logging.error(f"Error opening output file: {e}")
                sys.exit(1)
        else:
            logging.info("Writing to standard output.")
            output_stream = sys.stdout

        try:
            for line in input_stream:
                redacted_line = process_line(line, params_to_redact, redaction_string)
                output_stream.write(redacted_line)
        except Exception as e:
            logging.error(f"Error processing data: {e}")
        finally:
            if args.input != "-" and input_stream:
                input_stream.close()
            if args.output and output_stream:
                output_stream.close()

    except Exception as e:
        logging.critical(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()