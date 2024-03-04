import os
import sys
import json
import re


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
                methodline = 0
                for line_num, line in enumerate(lines, start=1):
                    if "FLAW" in line:
                        # Store the result in a dictionary
                        results[file] = results.get(file, [])
                        results[file].append(
                            {
                                "line": methodline,
                                "cwe": cwe_number,
                                "method": ("good" if isInsideGoodMethod else "bad"),
                            }
                        )
                    elif "good" in line and ";" not in line:
                        isInsideGoodMethod = True
                        methodline = line_num
                    elif ("bad" in line or "helperBad" in line) and ";" not in line:
                        isInsideGoodMethod = False
                        methodline = line_num
                # for line_num, line in enumerate(lines, start=1):
                #     record = {}
                #     found = False
                #     if ";" not in line:
                #         if "bad" in line or "helperBad(" in line:
                #             record["method"] = "bad"
                #             record["line"] = line_num
                #             found = True
                #         if "good(" in line or "G2B(" in line or "B2G(" in line:
                #             record["method"] = "good"
                #             record["line"] = line_num
                #             found = True
                #         if "helperGood" in line:
                #             record["method"] = "helper_good"
                #             record["line"] = line_num
                #             found = True
                #     if found:
                #         results[file] = results.get(file, [])
                #         results[file].append(record)

    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python search_juliet_pot_flaws.py path/to/juliet_dir")
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
    with open(f"../pot_flaws_{lang}.json", "w", encoding="UTF-8") as f:
        f.write(json.dumps(results, indent=4, sort_keys=True))
