import os
import sys
import json

def extract_cwe_number(filename):
    # Split the filename by underscores
    parts = filename.split('_')
    for part in parts:
        if part.startswith('CWE'):
            # Extract the CWE number
            cwe_number = part[3:]
            return cwe_number
    return None

def search_potential_flaw(juliet_directory):
    """Search the string 'POTENTIAL FLAW' in Juliet's testcases files"""
    results = []
    #juliet_directory = os.path.join(juliet_directory, "src/testcases")
    # Iterate through all files in juliet's directory
    for root, _, files in os.walk(juliet_directory):
        for file in files:
            if file == "Main.java" or file == "ServletMain.java":
                continue
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                cwe_number = extract_cwe_number(file)
                if cwe_number == None:
                    sys.stderr.write(f"No CWE for file {file}\n")
                    continue
                with open(file_path, 'r') as f:
                    # Read lines from the file
                    lines = f.readlines()
                    # Iterate through each line to find the string "POTENTIAL FLAW"
                    isInsideGoodMethod = None
                    for line_num, line in enumerate(lines, start=1):
                        if "POTENTIAL FLAW" in line:
                            # Store the result in a dictionary
                            results.append({
                                'file_path': file, #os.path.join("src/testcases", file),
                                'line': line_num + 1,
                                'cwe': cwe_number,
                                'category': "negative" if isInsideGoodMethod else "positive"
                            })
                        elif "good" in line:
                            isInsideGoodMethod = True
                        elif "bad" in line:
                            isInsideGoodMethod = False

    return results


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python search_potential_flaw.py <path/to/juliet_directory>")
        print("For example: python3 search_potential_flaw.py /path/to/juliet/")
        sys.exit(1)

    juliet_directory = sys.argv[1]

    # Search for potential flaws
    results = search_potential_flaw(juliet_directory)

    # Print results in JSON format
    print(json.dumps(results, indent=4))
