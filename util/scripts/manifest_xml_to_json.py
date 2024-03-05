import sys
import json


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 manifest_xml_to_json.py path/to/manifest.xml")
        sys.exit(1)

    # the manifest file (XML file) given by the user
    manifest_path = sys.argv[1]

    result = {}
    with open(manifest_path, "r") as f:
        last_filename = ""
        for line in f.readlines():
            if "path" in line:
                last_filename = line.split('"')[1]
            if "flaw" in line:
                spl = line.split('"')
                linenum = int(spl[1])
                cwe = spl[3]
                cwenum = str(int(cwe.split(":")[0].split("-")[1]))
                if f"CWE{cwenum}" not in last_filename[:9]:
                    continue
                if result.get(last_filename) is None:
                    result[last_filename] = []
                result[last_filename].append({"line": linenum, "cwe": cwenum})

        print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()