import json
import time
import os
import subprocess
import lib.output_parser as output_parser

debug = False
cwetree = {}


def get_cmd(tool, codedir, outdir):
    if tool != "cppcheck":
        outfile = f"{outdir}/{tool}.json"
    else:
        outfile = f"{outdir}/{tool}.txt"
    # Get the command to run with the correct tool and test suite
    match tool:
        case "semgrep":
            command = f"semgrep scan {codedir} --json -o {outfile}"
        case "horusec":
            command = (
                f"ulimit -n 2048 && horusec start -p {codedir} -D -O {outfile} -o json"
            )
        case "snyk":
            command = f"snyk code test {codedir} --json-file-output={outfile}"
        case "flawfinder":
            command = f"flawfinder -F --sarif {codedir} > {outfile}"
        case "cppcheck":
            command = f"cppcheck --template='{{cwe}}:{{file}}:{{line}}:{{severity}}' -q {codedir} --output-file={outfile}"

    return command, outfile


def run_tool(outdir, tool, codedir):
    command, outfile = get_cmd(tool, codedir, outdir)
    # Execute tool
    time_start = time.perf_counter()
    # In snyk always capture output, otherwise it prints too much
    capture = True if tool == "snyk" else (not debug)
    proc = subprocess.run(command, capture_output=capture, shell=True)
    if tool == "snyk" and debug:
        print(f"Snyk returned code {proc.returncode}")
    time_end = time.perf_counter()
    elapsed_time = time_end - time_start

    # Parse and filter
    filtered_data = output_parser.filter_data(tool, outfile)
    with open(f"{outdir}/{tool}_filtered.json", "w") as f:
        f.write(json.dumps(filtered_data, indent=4))

    # Aggregate
    aggr_data = output_parser.aggregate_cwe(filtered_data)
    with open(f"{outdir}/{tool}_vulns.json", "w") as f:
        f.write(json.dumps(aggr_data, indent=4, sort_keys=True))

    return elapsed_time, filtered_data, aggr_data


def run_horusec(outdir, tool, codedir):
    total_time = 0
    total_filtered_data = {}
    total_aggr_data = {"total": 0, "vulns": {}}

    folders = []
    for root, dirs, files in os.walk(codedir):
        # skip antbuild and skip subfolder (which are already included)
        if "antbuild" in root or "s0" in root or "s1" in root:
            continue
        if "src" in dirs or "testcases" in dirs:
            continue
        if "s01" in dirs:
            for subdir in dirs:
                folders.append(f"{root}/{subdir}")
        elif root != codedir:
            folders.append(root)

    for folder in folders:
        # Run on the directory
        run_time, run_filtered_data, run_aggr_data = run_tool(
            outdir=outdir, tool=tool, codedir=folder
        )

        # Aggregate results
        total_time += run_time
        total_filtered_data.update(run_filtered_data)
        total_aggr_data["total"] += run_aggr_data["total"]
        for cwe, cwe_count in run_aggr_data["vulns"].items():
            total_aggr_data["vulns"][cwe] = (
                total_aggr_data["vulns"].get(cwe, 0) + cwe_count
            )

    # Override previous json outputs
    with open(f"{outdir}/{tool}_filtered.json", "w", encoding="UTF-8") as f:
        f.write(json.dumps(total_filtered_data, indent=4))
    with open(f"{outdir}/{tool}_vulns.json", "w", encoding="UTF-8") as f:
        f.write(json.dumps(total_aggr_data, indent=4, sort_keys=True))

    return total_time, total_filtered_data, total_aggr_data


def run(outdir, tool, codedir, set_debug=False):

    global debug
    debug = set_debug

    if tool == "horusec":
        return run_horusec(
            outdir=outdir,
            tool=tool,
            codedir=codedir,
        )
    else:
        return run_tool(outdir=outdir, tool=tool, codedir=codedir)


def is_cwe_ancestor(cwe, ancestor):
    """Returns true if the given ancestor is an ancestor of the given cwe
    or the cwe and the ancestor are equal"""
    if cwe == ancestor:
        return True

    for parent in cwetree.get(cwe, []):
        if is_cwe_ancestor(parent, ancestor):
            return True
    return False


def find_vuln_in_manifest_list(vuln, list):
    for el in list:
        if vuln["line"] == el["line"]:
            vuln_cwe = vuln["cwe"]
            el_cwe = el["cwe"]
            if is_cwe_ancestor(vuln_cwe, el_cwe) or is_cwe_ancestor(
                el_cwe, vuln_cwe, cwetree
            ):
                return True
    return False


def get_method_line(filename, line, pot_flaws):
    """Given a filename and a line of a flaw, return the line from the pot_flaws"""
    greatest = -1
    # computes the greatest line lower than the given line
    for flaw in pot_flaws.get(filename, []):
        if flaw["line"] > line:
            break
        greatest = flaw["line"]

    return greatest if greatest != -1 else line


def are_cwe_related(first_cwe, second_cwe):
    """Given two CWEs, return if one is an anchestor of the other one"""
    return is_cwe_ancestor(first_cwe, second_cwe) or is_cwe_ancestor(
        second_cwe, first_cwe
    )


def find_flaw(flaw_line, flaw_cwe, flaws_list, by_cwe=True):
    """Given a flaw and a list of flaws, return if the flaw is in the list
    by comparing by line and CWE relationship"""
    for index, el in enumerate(flaws_list):
        el_line = el.get("method_line", el["line"])
        if flaw_line == el_line:
            if by_cwe:
                if are_cwe_related(flaw_cwe, el["cwe"], cwetree):
                    return el, index
            else:
                return el, index
    return None, -1


def is_one_related(cwe, cwes):
    for c in cwes:
        if are_cwe_related(c, cwe):
            return True
    return False


def confusion_matrix(pot_flaws_dict, sast_flaws_dict, cwe, cwe_tree):
    global cwetree
    cwetree = cwe_tree
    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for filename, found_list in sast_flaws_dict.items():
        for sast_flaw in found_list:
            sast_flaw["method_line"] = get_method_line(
                filename, sast_flaw["line"], pot_flaws_dict
            )
        found_list.sort(key=lambda d: d["method_line"])

    # compute positives. Check if true or false by looking at potential flaws
    # for each flaw found from SAST
    for filename, found_list in sast_flaws_dict.items():
        last_line = None
        juliet_cwe = None
        last_cwes = []
        tp_found_num = 0

        juliet_flaws_num_per_line = {}
        for juliet_flaw in pot_flaws_dict.get(filename, []):
            juliet_flaws_num_per_line[juliet_flaw["line"]] = (
                juliet_flaws_num_per_line.get(juliet_flaw["line"], 0) + 1
            )

        # for each flaw found from SAST in the specified filename
        for sast_flaw in found_list:

            found, index = find_flaw(
                sast_flaw["method_line"],
                sast_flaw["cwe"],
                pot_flaws_dict.get(filename, []),
                by_cwe=False,
            )

            if sast_flaw["method_line"] == last_line:
                if is_one_related(sast_flaw["cwe"], last_cwes):
                    if not found:
                        if tp_found_num >= juliet_flaws_num_per_line.get(
                            sast_flaw["method_line"], 0
                        ):
                            continue
            else:
                last_cwes = []
                juliet_cwe = None
                last_line = sast_flaw["method_line"]

            if found:  # found but CWE may not be related
                are_related = are_cwe_related(sast_flaw["cwe"], found["cwe"])
                if found["method"] == "bad" and are_related:
                    tp += 1
                    tp_found_num += 1
                else:
                    fp += 1
                juliet_cwe = found["cwe"]
                last_cwes.append(sast_flaw["cwe"])
                pot_flaws_dict.get(filename).pop(index)
            else:
                if are_cwe_related(sast_flaw["cwe"], juliet_cwe):
                    # l'ho trovato ma un record precedente me l'aveva tolto
                    tp += 1
                    tp_found_num += 1
                else:
                    if not is_one_related(sast_flaw["cwe"], last_cwes):
                        fp += 1
                last_cwes.append(sast_flaw["cwe"])

    # compute negatives, and check if the SAST found or didn't find a negative
    # for each potential flaw
    for filename, pot_flaws_list in pot_flaws_dict.items():
        # filter by required CWE, if any
        if cwe is not None:
            curr_cwe = filename.split("_")[0][3:]
            if curr_cwe != cwe:
                continue

        # for each potential flaw of the file, search if it was found by SAST
        for pot_flaw in pot_flaws_list:
            # if the potential flaw is here is because it was not found by SAST
            # not found by SAST
            if pot_flaw["method"] == "good":
                tn += 1  # true negative if it is in a good method
            else:
                fn += 1  # false negative if it is in a bad method

    p = tp + fp
    n = tn + fn

    retdict = {
        "false positive": fp,
        "true positive": tp,
        "false negative": fn,
        "true negative": tn,
        "accuracy": (tp + tn) / (p + n) if p + n > 0 else 0,
        "precision": tp / p if p > 0 else 0,
        "recall": tp / (tp + fn) if fp + fn > 0 else 0,
        "specificity": tn / (tn + fp) if tn + fp > 0 else 0,
    }

    return retdict
