import sys


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 filter_cwe_xml.py path/to/699.xml")
        sys.exit(1)

    # the manifest file (XML file) given by the user
    cwe_xml = sys.argv[1]
    print('<?xml version="1.0" encoding="UTF-8"?>')
    with open(cwe_xml, "r") as f:
        for line in f.readlines():
            if "<Weakness_Or" in line or "</Weakness_Or" in line:
                continue
            if (
                "<Weakness" in line
                or "<Related_Weakness" in line
                or "</Weakness" in line
                or "</Related_W" in line
            ):
                # print to stdout
                print(line, end="")


if __name__ == "__main__":
    main()
