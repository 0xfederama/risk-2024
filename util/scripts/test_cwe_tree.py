import sys
import json


def full_traversal(cwe, tree):
    if cwe not in tree:
        return
    for parent in tree[cwe]:
        full_traversal(parent, tree)


def test_traversal(cwe_tree):
    for cwe in cwe_tree:
        print(type(cwe))
        print("Traversal of", cwe, end="")
        full_traversal(cwe, cwe_tree)
        print(". Success")


def is_cwe_ancestor(cwe, ancestor, tree):
    """Returns true if the given ancestor is an ancestor of the given cwe
    or the cwe and the ancestor are equal"""
    if cwe == ancestor:
        return True

    for parent in tree.get(cwe, []):
        if is_cwe_ancestor(parent, ancestor, tree):
            return True
    return False


def test_ancestor(cwe1, cwe2, cwe_tree, value):
    ret = is_cwe_ancestor(cwe1, cwe2, cwe_tree)
    if ret == value:
        print(f"[ OK ]: {value}")
    else:
        print(f"[FAIL]: {ret} should have been {value}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 test_cwe_tree.py path/to/cwe_tree_full.json")
        sys.exit(1)

    # the manifest file (XML file) given by the user
    cwe_json_file_path = sys.argv[1]
    # Read the cwe tree from file
    cwe_tree = {}
    with open(cwe_json_file_path, "r") as f:
        cwe_tree = json.load(f)

    # test_traversal(cwe_tree)
    test_ancestor("118", "664", cwe_tree, True)
    test_ancestor("664", "118", cwe_tree, False)
    test_ancestor("120", "119", cwe_tree, True)
    test_ancestor("126", "119", cwe_tree, True)
    test_ancestor("126", "120", cwe_tree, False)
    test_ancestor("195", "664", cwe_tree, True)


if __name__ == "__main__":
    main()
