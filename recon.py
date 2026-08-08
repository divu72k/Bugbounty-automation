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
    print("Error: No subdomains found in the input file.")
    exit(1)

res = subprocess.run(
    ["httpx", "-silent", "-status-code", "-title"],
    input="\n".join(subd),
    text=True,
    capture_output=True
)

if res.returncode != 0:
    print("httpx encountered an error:")
    print(res.stderr)
    exit(1)

alive = [
    line.strip()
    for line in res.stdout.splitlines()
    if line.strip()
]

try:
    with open(output_file, "w") as f:
        f.write("\n".join(alive))
except OSError as e:
    print(f"Error writing output file: {e}")
    exit(1)

print("\n--- Results ---")
print(f"Total unique subdomains : {len(subd)}")
print(f"Alive hosts             : {len(alive)}")
print(f"Unresponsive hosts      : {len(subd) - len(alive)}")
print(f"Results saved to        : {output_file}")
