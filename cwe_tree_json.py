import sys
import json


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 cwe_tree_json.py path/to/cwe_tree.xml")
        sys.exit(1)

    # the manifest file (XML file) given by the user
    cwe_xml = sys.argv[1]
    with open(cwe_xml, "r") as f:
        cwe_tree = {}
        child_cwe = ""
        for line in f.readlines():
            if "Weakness ID=" in line:
                child_cwe = line.split('"')[1]
            if 'Related_Weakness Nature="ChildOf"' in line:
                parent_cwe = line.split('"')[3]
                if cwe_tree.get(child_cwe) is None:
                    cwe_tree[child_cwe] = [parent_cwe]
                else:
                    if parent_cwe not in cwe_tree[child_cwe]:
                        cwe_tree[child_cwe].append(parent_cwe)

        with open("cwe_tree.json", "w", encoding="UTF-8") as f:
            f.write(json.dumps(cwe_tree, indent=4, sort_keys=True))


if __name__ == "__main__":
    main()
