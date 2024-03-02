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
                result[last_filename] = {"line": linenum, "cwe": cwenum}

    # print the json result to stdout
    print(json.dumps(result, indent=4))


if __name__ == "__main__":
    main()
