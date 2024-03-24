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
    results = {}
    # Iterate through all files in juliet's directory
    for root, _, files in os.walk(juliet_directory):
        for file in files:
            file_path = os.path.join(root, file)
            cwe_number = extract_cwe_number(file)
            if cwe_number is None:
                continue
            with open(file_path, "r") as f:
                # Read lines from the file
                lines = f.readlines()
                sink_decl = False
                sink_call = False
                for line in lines:
                    if "Sink(" in line:
                        if ";" in line:
                            sink_call = True
                        else:
                            sink_decl = True
                # case, sink declaration, may have sink call
                if sink_decl:
                    method_line = 0
                    # search and consider only sinks
                    is_in_bad_sink_method = False # badSink, G2BSink
                    is_in_good_sink_method = False # B2GSink
                    for line_num, line in enumerate(lines, start=1):
                        if "FLAW" in line or "FIX" in line:
                            if not is_in_bad_sink_method and not is_in_good_sink_method:
                                continue
                            if is_in_good_sink_method:
                                method = "good"
                            elif is_in_bad_sink_method:
                                method = "bad"
                            results[file] = results.get(file, [])
                            for a in results[file]:
                                    if a["line"] == method_line:
                                        continue
                            results[file].append(
                                {
                                    "line": method_line,
                                    "cwe": cwe_number,
                                    "method": method,
                                }
                            )
                        elif ("badSink" in line or "G2BSink" in line ) and ";" not in line:
                            is_in_bad_sink_method = True
                            method_line = line_num
                        elif ("B2GSink" in line) and ";" not in line:
                            is_in_good_sink_method = True
                            method_line = line_num
                        elif ("G2B(" in line or "B2G(" in line or "good(" in line or "bad(" in line or "") and ";" not in line:
                            is_in_good_sink_method = False
                            is_in_bad_sink_method = False
                else: # case no sink declaration, no sink call
                    if not sink_call:
                        # base case
                        # Iterate through each line to find the string "POTENTIAL FLAW"
                        is_in_good_method = None
                        method_line = 0
                        for line_num, line in enumerate(lines, start=1):
                            if "FLAW" in line or "FIX" in line:
                                # Store the result in a dictionary
                                results[file] = results.get(file, [])
                                for a in results[file]:
                                    if a["line"] == method_line:
                                        continue
                                results[file].append(
                                    {
                                        "line": method_line,
                                        "cwe": cwe_number,
                                        "method": ("good" if is_in_good_method else "bad"),
                                    }
                                )
                            elif ("good" in line or "B2G" in line or "G2B" in line) and ";" not in line:
                                is_in_good_method = True
                                method_line = line_num
                            elif ("bad" in line) and ";" not in line:
                                is_in_good_method = False
                                method_line = line_num

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
