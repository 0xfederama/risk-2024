import os
import sys
import json


def extract_cwe_number(filename):
    # Split the filename by underscores
    parts = filename.split("_")
    for part in parts:
        if part.startswith("CWE"):
            # Extract the CWE number
            cwe_number = part[3:]
            return cwe_number
    return None


def search_potential_flaws(juliet_directory):
    """Search the string 'POTENTIAL FLAW' in Juliet's testcases files"""
    results = {}
    # Iterate through all files in juliet's directory
    for root, _, files in os.walk(juliet_directory):
        for file in files:
            file_path = os.path.join(root, file)
            cwe_number = extract_cwe_number(file)
            if cwe_number is None:
                sys.stderr.write(f"No CWE for file {file}\n")
                continue
            with open(file_path, "r") as f:
                # Read lines from the file
                lines = f.readlines()
                # Iterate through each line to find the string "POTENTIAL FLAW"
                isInsideGoodMethod = None
                for line_num, line in enumerate(lines, start=1):
                    if "FLAW" in line:
                        # Store the result in a dictionary
                        results[file] = results.get(file, [])
                        results[file].append(
                            {
                                "line": line_num + 1,
                                "cwe": cwe_number,
                                "category": (
                                    "negative" if isInsideGoodMethod else "positive"
                                ),
                            }
                        )
                    elif "good" in line:
                        isInsideGoodMethod = True
                    elif "bad" in line:
                        isInsideGoodMethod = False

    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python search_juliet_vulns.py <path/to/juliet_directory>")
        print("For example: python3 search_juliet_vulns.py /path/to/juliet/")
        sys.exit(1)

    juliet_directory = sys.argv[1]
    lang = ""
    if "java" in juliet_directory:
        lang = "java"
    elif "csh" in juliet_directory:
        lang = "csharp"
    elif "cpp" in juliet_directory:
        lang = "cpp"
    else:
        print("Error")
        exit(1)

    # Search for potential flaws
    results = search_potential_flaws(juliet_directory)

    # Print results in JSON format
    with open(f"util/juliet_{lang}_flaws.json", "w", encoding="UTF-8") as f:
        f.write(json.dumps(results, indent=4, sort_keys=True))
