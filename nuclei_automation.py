#!/usr/bin/env python3

import json
import re
import subprocess
import sys


# ============================================================================
# Configuration
# ============================================================================

NUCLEI_TARGET_FILE = "nuclei_targets.txt"
NUCLEI_RAW_OUTPUT = "nuclei-results.jsonl"
NUCLEI_REPORT = "nuclei-report.txt"

HTTPX_MATCH_CODES = ["200", "403"]

NUCLEI_SEVERITIES = "info,low,medium,high,critical"

# Nuclei request rate and concurrency.
NUCLEI_RATE_LIMIT = "50"
NUCLEI_CONCURRENCY = "25"


# ============================================================================
# Helper functions
# ============================================================================

def run_command(command, input_data=None):
    """
    Execute an external command and return its CompletedProcess object.

    stdout and stderr are captured so that errors can be displayed cleanly.
    """

    return subprocess.run(
        command,
        input=input_data,
        text=True,
        capture_output=True
    )


def parse_httpx_output(httpx_output):
    """
    Extract clean URLs from httpx output.

    httpx is configured to return output similar to:

        https://example.com [200]
        https://admin.example.com [403]

    This function removes the trailing status-code annotation and returns:

        https://example.com
        https://admin.example.com
    """

    status_code_regex = re.compile(r"\s+\[\d{3}\]\s*$")

    clean_urls = []

    for line in httpx_output.splitlines():

        line = line.strip()

        if not line:
            continue

        url = status_code_regex.sub("", line).strip()

        if url:
            clean_urls.append(url)

    return clean_urls


def load_nuclei_results(filename):
    """
    Read Nuclei's JSONL output.

    Nuclei JSONL contains one JSON object per line.

    Malformed lines are skipped rather than terminating the entire
    reporting process.
    """

    results = []

    try:
        with open(filename, "r", encoding="utf-8") as f:

            for line_number, line in enumerate(f, start=1):

                line = line.strip()

                if not line:
                    continue

                try:
                    result = json.loads(line)
                    results.append(result)

                except json.JSONDecodeError:
                    print(
                        f"[!] Warning: malformed JSON on line "
                        f"{line_number}, skipping."
                    )

    except FileNotFoundError:
        print(f"[!] Nuclei output '{filename}' was not found.")
        return []

    return results


def normalize_finding(result):
    """
    Extract only the useful fields from a raw Nuclei result.

    The original JSON object can contain very large request/response
    structures. These are intentionally excluded from the readable
    report.

    The original JSONL file remains untouched and contains the complete
    Nuclei result.
    """

    info = result.get("info", {})

    return {
        "template_id": result.get("template-id", "unknown"),
        "name": info.get("name", "Unknown Finding"),
        "severity": info.get("severity", "unknown").upper(),

        "host": result.get("host", "unknown"),
        "port": result.get("port", ""),
        "ip": result.get("ip", "unknown"),
        "matched_at": result.get("matched-at", "unknown"),

        "type": result.get("type", ""),
        "extracted_results": result.get("extracted-results", []),

        # Useful when available in Nuclei output.
        "matcher_status": result.get("matcher-status", None),
    }


def deduplicate_findings(findings):
    """
    Remove duplicate findings.

    A finding is considered a duplicate when the same template matches
    the same host and port.

    This prevents multiple identical entries from making the report
    unnecessarily noisy.
    """

    unique_findings = []
    seen = set()

    for finding in findings:

        key = (
            finding["template_id"],
            finding["host"],
            finding["port"]
        )

        if key in seen:
            continue

        seen.add(key)
        unique_findings.append(finding)

    return unique_findings


def write_nuclei_report(findings, filename):
    """
    Generate a human-readable Nuclei report.

    The report intentionally excludes Nuclei's massive raw response
    objects. Those remain available in nuclei-results.jsonl.
    """

    with open(filename, "w", encoding="utf-8") as report:

        report.write("NUCLEI RECONNAISSANCE REPORT\n")
        report.write("=" * 70 + "\n\n")

        report.write(
            f"Total findings : {len(findings)}\n"
        )

        report.write("\n")

        if not findings:
            report.write("No Nuclei findings were returned.\n")
            return

        # --------------------------------------------------------------------
        # Summary by severity
        # --------------------------------------------------------------------

        severity_counts = {}

        for finding in findings:
            severity = finding["severity"]

            severity_counts[severity] = (
                severity_counts.get(severity, 0) + 1
            )

        report.write("SEVERITY SUMMARY\n")
        report.write("-" * 70 + "\n")

        severity_order = [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
            "UNKNOWN"
        ]

        for severity in severity_order:

            count = severity_counts.get(severity, 0)

            if count:
                report.write(
                    f"{severity:<10}: {count}\n"
                )

        report.write("\n")

        # --------------------------------------------------------------------
        # Individual findings
        # --------------------------------------------------------------------

        for number, finding in enumerate(findings, start=1):

            report.write("=" * 70 + "\n")

            report.write(
                f"[{number}] "
                f"[{finding['severity']}] "
                f"{finding['name']}\n"
            )

            report.write("=" * 70 + "\n")

            report.write(
                f"Host       : {finding['host']}\n"
            )

            if finding["port"]:
                report.write(
                    f"Port       : {finding['port']}\n"
                )

            report.write(
                f"IP         : {finding['ip']}\n"
            )

            report.write(
                f"Template   : {finding['template_id']}\n"
            )

            report.write(
                f"Matched At : {finding['matched_at']}\n"
            )

            if finding["type"]:
                report.write(
                    f"Type       : {finding['type']}\n"
                )

            # ---------------------------------------------------------------
            # Extracted results
            # ---------------------------------------------------------------

            extracted = finding["extracted_results"]

            if extracted:

                report.write("\n")
                report.write("Extracted Results:\n")

                for value in extracted:

                    # Nuclei sometimes returns extracted data as a string
                    # representation of a list.
                    if isinstance(value, str):
                        report.write(
                            f"  - {value}\n"
                        )
                    else:
                        report.write(
                            f"  - {json.dumps(value)}\n"
                        )

            report.write("\n")


# ============================================================================
# Main workflow
# ============================================================================

def main():

    # ------------------------------------------------------------------------
    # Get input files
    # ------------------------------------------------------------------------

    input_file = input(
        "Enter the file containing the subdomains: "
    ).strip()

    output_file = input(
        "Enter the output file for httpx results: "
    ).strip()

    if not input_file:
        print("[!] No input file specified.")
        sys.exit(1)

    if not output_file:
        print("[!] No output file specified.")
        sys.exit(1)

    # ------------------------------------------------------------------------
    # Read subdomains
    # ------------------------------------------------------------------------

    print("\n[*] Reading subdomains...")

    try:

        with open(input_file, "r", encoding="utf-8") as f:

            # Remove empty lines and duplicates while preserving order.
            subdomains = list(dict.fromkeys(
                line.strip()
                for line in f
                if line.strip()
            ))

    except FileNotFoundError:

        print(
            f"[!] Error: '{input_file}' was not found."
        )

        sys.exit(1)

    except OSError as e:

        print(
            f"[!] Error reading '{input_file}': {e}"
        )

        sys.exit(1)

    if not subdomains:

        print("[!] No subdomains found.")
        sys.exit(1)

    print(
        f"[+] Loaded {len(subdomains)} unique subdomains."
    )

    # ------------------------------------------------------------------------
    # Run httpx
    # ------------------------------------------------------------------------

    print("\n[*] Running httpx...")

    httpx_command = [
        "httpx-toolkit",
        "-silent",
        "-status-code",
        "-mc",
        ",".join(HTTPX_MATCH_CODES)
    ]

    httpx = run_command(
        httpx_command,
        input_data="\n".join(subdomains)
    )

    if httpx.returncode != 0:

        print("\n[!] httpx encountered an error:")

        if httpx.stderr:
            print(httpx.stderr)

        sys.exit(1)

    # ------------------------------------------------------------------------
    # Process httpx results
    # ------------------------------------------------------------------------

    httpx_results = [
        line.strip()
        for line in httpx.stdout.splitlines()
        if line.strip()
    ]

    clean_urls = parse_httpx_output(
        httpx.stdout
    )

    # ------------------------------------------------------------------------
    # Save httpx output
    # ------------------------------------------------------------------------

    try:

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as f:

            f.write("\n".join(httpx_results))

            if httpx_results:
                f.write("\n")

        with open(
            NUCLEI_TARGET_FILE,
            "w",
            encoding="utf-8"
        ) as f:

            f.write("\n".join(clean_urls))

            if clean_urls:
                f.write("\n")

    except OSError as e:

        print(
            f"[!] Error writing httpx results: {e}"
        )

        sys.exit(1)

    # ------------------------------------------------------------------------
    # Display httpx statistics
    # ------------------------------------------------------------------------

    print("\n--- HTTPX Results ---")

    print(
        f"Total subdomains : {len(subdomains)}"
    )

    print(
        f"200/403 hosts    : {len(clean_urls)}"
    )

    print(
        f"Results saved to  : {output_file}"
    )

    print(
        f"Nuclei targets    : {NUCLEI_TARGET_FILE}"
    )

    # ------------------------------------------------------------------------
    # Stop if httpx found nothing
    # ------------------------------------------------------------------------

    if not clean_urls:

        print(
            "\n[!] No HTTP 200/403 targets discovered."
        )

        print(
            "[*] Skipping Nuclei."
        )

        return

    # ------------------------------------------------------------------------
    # Run Nuclei
    # ------------------------------------------------------------------------

    print("\n[*] Running nuclei...")

    nuclei_command = [
        "nuclei",

        # Read targets generated by httpx.
        "-l",
        NUCLEI_TARGET_FILE,

        # Automatically select applicable templates.
        "-as",

        # Include all desired severities.
        "-s",
        NUCLEI_SEVERITIES,

        # Limit request rate.
        "-rl",
        NUCLEI_RATE_LIMIT,

        # Number of concurrent workers.
        "-c",
        NUCLEI_CONCURRENCY,

        # Machine-readable JSON Lines output.
        "-jsonl",

        # Preserve complete raw findings.
        "-o",
        NUCLEI_RAW_OUTPUT
    ]

    nuclei = run_command(
        nuclei_command
    )

    if nuclei.returncode != 0:

        print("\n[!] Nuclei encountered an error.")

        if nuclei.stderr:
            print(nuclei.stderr)

        sys.exit(1)

    print("[+] Nuclei scan completed.")

    # ------------------------------------------------------------------------
    # Parse Nuclei results
    # ------------------------------------------------------------------------

    print(
        "\n[*] Parsing Nuclei JSONL results..."
    )

    raw_results = load_nuclei_results(
        NUCLEI_RAW_OUTPUT
    )

    if not raw_results:

        print(
            "[+] Nuclei returned no findings."
        )

        # Still create an empty report so the workflow has a predictable
        # output file.
        write_nuclei_report(
            [],
            NUCLEI_REPORT
        )

        print(
            f"[+] Empty report saved to: {NUCLEI_REPORT}"
        )

        return

    # Convert large raw Nuclei objects into compact findings.
    findings = [
        normalize_finding(result)
        for result in raw_results
    ]

    # Remove duplicate template/host/port combinations.
    unique_findings = deduplicate_findings(
        findings
    )

    # ------------------------------------------------------------------------
    # Generate readable report
    # ------------------------------------------------------------------------

    write_nuclei_report(
        unique_findings,
        NUCLEI_REPORT
    )

    # ------------------------------------------------------------------------
    # Final statistics
    # ------------------------------------------------------------------------

    print("\n--- Nuclei Results ---")

    print(
        f"Raw findings      : {len(raw_results)}"
    )

    print(
        f"Unique findings   : {len(unique_findings)}"
    )

    print(
        f"Raw JSONL         : {NUCLEI_RAW_OUTPUT}"
    )

    print(
        f"Readable report   : {NUCLEI_REPORT}"
    )

    print("\n[+] Recon pipeline completed successfully.")


# ============================================================================
# Entry point
# ============================================================================

if __name__ == "__main__":
    main()
