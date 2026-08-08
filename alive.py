#!/usr/bin/env python3

import subprocess

input_file = input("Enter the file containing the subdomains: ")
output_file = input("Enter the name of the output file: ")

try:
    with open(input_file, "r") as f:
        subd = list(dict.fromkeys(
            line.strip()
            for line in f
            if line.strip()
        ))
except FileNotFoundError:
    print(f"Error: File '{input_file}' was not found.")
    exit(1)

if not subd:
    print("No subdomains found.")
    exit(1)

res = subprocess.run(
    [
        "httpx-toolkit",
        "-silent",
        "-status-code"
    ],
    input="\n".join(subd),
    text=True,
    capture_output=True
)

if res.returncode != 0:
    print("httpx encountered an error:")
    print(res.stderr)
    exit(1)

# Keep only HTTP 200 and 403 responses
alive = [
    line.strip()
    for line in res.stdout.splitlines()
    if "[200]" in line or "[403]" in line
]

with open(output_file, "w") as f:
    f.write("\n".join(alive))

print("\n--- Results ---")
print(f"Total subdomains : {len(subd)}")
print(f"200/403 hosts    : {len(alive)}")
print(f"Other/unreachable: {len(subd) - len(alive)}")
print(f"Results saved to  : {output_file}")
