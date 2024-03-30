import json
import sys

families = {
    "Authentication and access control": [
        15,
        247,
        256,
        259,
        272,
        284,
        491,
        500,
        549,
        560,
        566,
        582,
        607,
        613,
        614,
        620,
        784,
    ],
    "Buffer handling": [121, 122, 123, 124, 126, 127, 242, 680, 785],
    "Code Quality": [398, 477, 478, 484, 547, 561, 563, 570, 571, 585, 676],
    "Control Flow Management": [
        180,
        364,
        366,
        367,
        382,
        383,
        479,
        483,
        572,
        584,
        606,
        609,
        674,
        698,
        764,
        764,
        765,
        832,
        833,
        835,
    ],
    "Encryption and Randomness": [
        315,
        319,
        327,
        328,
        329,
        330,
        336,
        338,
        523,
        759,
        760,
        780,
    ],
    "Error Handling": [248, 252, 253, 273, 390, 391, 392, 396, 397, 440, 617],
    "File Handling": [23, 36, 377, 378, 379, 675],
    "Information Leaks": [204, 209, 226, 244, 497, 499, 533, 534, 535, 591, 598, 615],
    "Initialization and Shutdown": [
        400,
        401,
        404,
        415,
        416,
        457,
        459,
        568,
        580,
        586,
        590,
        665,
        672,
        761,
        762,
        772,
        773,
        775,
        789,
    ],
    "Injection": [78, 80, 81, 83, 89, 90, 113, 129, 134, 436, 427, 470, 601, 643],
    "Malicius Logic": [111, 114, 304, 321, 325, 506, 510, 511, 514, 546],
    "Miscellaneous": [
        188,
        222,
        223,
        464,
        475,
        480,
        481,
        482,
        486,
        489,
        579,
        581,
        597,
        605,
        666,
        685,
        688,
        758,
    ],
    "Number Handling": [190, 191, 193, 194, 195, 196, 197, 369, 681],
    "Pointer and Reference Handling": [
        374,
        395,
        467,
        468,
        469,
        476,
        562,
        587,
        588,
        690,
        843,
    ],
}


def is_cwe_ancestor(cwe, ancestor, tree):
    """Returns true if the given ancestor is an ancestor of the given cwe
    or the cwe and the ancestor are equal"""
    if cwe == ancestor:
        return True

    for parent in tree.get(cwe, []):
        if is_cwe_ancestor(parent, ancestor, tree):
            return True
    return False


def cwe_relationship(first_cwe, second_cwe, cwe_tree):
    if first_cwe == cwe_tree:
        return True

    if is_cwe_ancestor(first_cwe, second_cwe, cwe_tree):
        return True

    return is_cwe_ancestor(second_cwe, first_cwe, cwe_tree)


def get_family_name(cwe_to_find, cwe_tree):
    for name, cwes in families.items():
        for cwe in cwes:
            if cwe_relationship(str(cwe), cwe_to_find, cwe_tree):
                return name
    return "Unknown"


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 get_cwe_families.py path/to/cwe_tree_full.json")
        sys.exit(1)

    # the cwe tree file given by the user
    cwe_json_file_path = sys.argv[1]
    # Read the cwe tree from file
    cwe_tree = {}
    with open(cwe_json_file_path, "r") as f:
        cwe_tree = json.load(f)

    sast_res = {
        "sem_java": [
            22,
            78,
            79,
            89,
            90,
            93,
            113,
            319,
            326,
            327,
            328,
            329,
            352,
            470,
            489,
            502,
            601,
            614,
            643,
            798,
            1004,
        ],
        "sny_java": [
            15,
            23,
            78,
            79,
            89,
            90,
            113,
            134,
            209,
            319,
            326,
            327,
            470,
            547,
            601,
            613,
            614,
            798,
            916,
            1004,
        ],
        "hor_java": [78, 79, 89, 90, 276, 326, 327, 329, 330, 539, 719, 780, 798],
        "sem_csh": [78, 89, 502, 614, 643, 798, 1004],
        "sny_csh": [
            23,
            78,
            79,
            89,
            90,
            94,
            200,
            327,
            547,
            601,
            614,
            643,
            798,
            916,
            1004,
        ],
        "hor_csh": [89, 90, 326, 338, 614, 798, 1004],
        "sem_cpp": [14, 78, 125, 415, 416, 467],
        "sny_cpp": [122, 170, 190, 290, 369, 401, 415, 416, 476, 775, 910],
        "cpc_cpp": [
            190,
            369,
            398,
            401,
            404,
            415,
            416,
            457,
            476,
            562,
            590,
            628,
            664,
            672,
            685,
            758,
            762,
            775,
            786,
            788,
            910,
        ],
        "flf_cpp": [20, 78, 120, 126, 134, 190, 250, 327, 362, 807],
    }

    for sast_name, res in sast_res.items():
        groups = {}
        for cwe in res:
            group_name = get_family_name(cwe_to_find=str(cwe), cwe_tree=cwe_tree)
            groups[group_name] = groups.get(group_name, [])
            groups[group_name].append(cwe)

        sorted_groups = dict(sorted(groups.items()))
        for group_name, cwes_in_group in sorted_groups.items():
            count = len(cwes_in_group)
            if group_name == "Unknown":
                print(f"[{sast_name}] {cwes_in_group} are Unknown")
                continue
            print(f"[{sast_name}] {group_name}: {count} of {len(families[group_name])}")
        print()


if __name__ == "__main__":
    main()
