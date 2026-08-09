#!/usr/bin/env python3

import re
import subprocess

input_file = input("Enter the file containing the subdomains: ")
output_file = input("Enter the output file: ")

try:
    with open(input_file, "r") as f:
        subdomains = list(dict.fromkeys(
            line.strip()
            for line in f
            if line.strip()
        ))
except FileNotFoundError:
    print(f"Error: '{input_file}' was not found.")
    exit(1)

if not subdomains:
    print("No subdomains found.")
    exit(1)


print("\n[*] Running httpx...")

res = subprocess.run(
    [
        "httpx-toolkit",
        "-silent",
        "-status-code",
        "-mc", "200,403"
    ],
    input="\n".join(subdomains),
    text=True,
    capture_output=True
)

if res.returncode != 0:
    print("httpx encountered an error:")
    print(res.stderr)
    exit(1)

httpx_results = [
    line.strip()
    for line in res.stdout.splitlines()
    if line.strip()
]

clean_file = "nuclei_targets.txt"

status_code_regex = re.compile(r"\s+\[\d{3}\]\s*$")

clean_urls = []

for line in httpx_results:
    url = status_code_regex.sub("", line).strip()

    if url:
        clean_urls.append(url)

with open(output_file, "w") as f:
    f.write("\n".join(httpx_results))

with open(clean_file, "w") as f:
    f.write("\n".join(clean_urls))

print("\n--- HTTPX Results ---")
print(f"Total subdomains : {len(subdomains)}")
print(f"200/403 hosts    : {len(clean_urls)}")
print(f"Results saved to  : {output_file}")
print(f"Nuclei targets    : {clean_file}")

print("\n[*] Running nuclei...")

nuclei = subprocess.run(
    [
        "nuclei",
        "-l", clean_file,
        "-as"
    ],
    text=True
)

if nuclei.returncode != 0:
    print("\nNuclei encountered an error.")
    exit(1)

print("\n[*] Nuclei scan completed.")
