import sys
import json

def full_traversal(cwe, tree):
    if cwe not in tree:
        return
    for parent in tree[cwe]:
        full_traversal(parent, tree)

def test_traversal(cwe_tree):
    for cwe in cwe_tree:
        print("Traversal of", cwe, end="")
        full_traversal(cwe, cwe_tree)
        print(". Success")

def is_cwe_anchestor(cwe, anchestor, tree):
    """Returns true if the given anchestor is an anchestor of the given cwe or the cwe and the anchestor are equal"""
    if cwe == anchestor:
        return True
        
    for parent in tree[cwe]:
        if is_cwe_anchestor(parent, anchestor, tree):
            return True
    return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 test_cwe_tree.py path/to/cwe_tree.json")
        sys.exit(1)

    # the manifest file (XML file) given by the user
    cwe_json_file_path = sys.argv[1]
    # Read the cwe tree from file
    cwe_tree = {}
    with open(cwe_json_file_path, "r") as f:
        cwe_tree = json.load(f)

    #test_traversal(cwe_tree)
    print(is_cwe_anchestor("118", "664", cwe_tree)) # 118 is child of 664
    print(is_cwe_anchestor("195", "664", cwe_tree)) # 664 is anchestor of 195 (195 -> 681 -> 704 -> 664)


if __name__ == "__main__":
    main()
