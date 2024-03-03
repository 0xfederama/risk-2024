import json
import time
import os
import lib.output_parser as output_parser

debug = False


def get_cmd(tool, codedir, outdir):
    if tool != "cppcheck":
        outfile = f"{outdir}/{tool}.json"
    else:
        outfile = f"{outdir}/{tool}.txt"
    # Get the command to run with the correct tool and test suite
    redir = ""
    if not debug or tool == "snyk":
        redir = " &> /dev/null"
    command = ""
    match tool:
        case "semgrep":
            command = f"semgrep scan {codedir} --json -o {outfile}" + redir
        case "horusec":
            command = f"horusec start -p {codedir} -D -O {outfile} -o json" + redir
        case "snyk":
            command = f"snyk code test {codedir} --json-file-output={outfile}" + redir
        case "flawfinder":
            command = f"flawfinder --sarif {codedir} > {outfile}"
        case "cppcheck":
            command = f"cppcheck --template='{{cwe}}:{{file}}:{{line}}:{{severity}}' -q {codedir} --output-file={outfile}"

    return command, outfile


def run_tool(outdir, tool, codedir):
    command, outfile = get_cmd(tool, codedir, outdir)
    # Execute tool
    time_start = time.perf_counter()
    os.system(command)
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
    total_filtered_data = []
    total_aggr_data = {"total": 0, "vulns": {}}
    print(f"{codedir}/src/testcases/")

    for folder in os.listdir(f"{codedir}/src/testcases/"):
        folder = f"{codedir}/src/testcases/{folder}"
        if "CWE" not in folder:
            continue

        # Run on the directory
        print("RUNNING ON DIR:", folder)
        run_time, run_filtered_data, run_aggr_data = run_tool(
            outdir=outdir, tool=tool, codedir=folder
        )

        # Aggregate results
        total_time += run_time
        total_filtered_data += run_filtered_data
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

    if tool == "horusec" and "CWE" not in codedir:
        return run_horusec(
            outdir=outdir,
            tool=tool,
            codedir=codedir,
        )
    else:
        return run_tool(outdir=outdir, tool=tool, codedir=codedir)


def is_cwe_ancestor(cwe, ancestor, cwe_tree):
    """Returns true if the given ancestor is an ancestor of the given cwe
    or the cwe and the ancestor are equal"""
    if cwe == ancestor:
        return True

    for parent in cwe_tree.get(cwe, []):
        if is_cwe_ancestor(parent, ancestor, cwe_tree):
            return True
    return False


def find_vuln_in_manifest_list(vuln, list, cwe_tree):
    for el in list:
        if vuln["line"] == el["line"]:
            vuln_cwe = vuln["cwe"]
            el_cwe = el["cwe"]
            if is_cwe_ancestor(vuln_cwe, el_cwe, cwe_tree) or is_cwe_ancestor(
                el_cwe, vuln_cwe, cwe_tree
            ):
                if vuln_cwe != el_cwe:
                    print(f"CWE {vuln_cwe} and {el_cwe} related")
                return True
    return False


def confusion_matrix(pot_flaws, manifest_flaws, sast_flaws, cwe, cwe_tree):
    """
    For each vuln found by the SAST:
        If found in manifest:
            True positive
        Else:
            If found in pot flaws file:
                If in method bad:
                    Ignore it
                Else:
                    False positive
            Else:
                False positive

    For each vuln found in manifest:
        If found in SAST:
            Ignore it (true positive, but we have already count it)
        Else:
            False negative

    For each potential flaw:
        cwe different -> skip
        method good, sast found -> FP
        method good, sast not found -> TN
        method bad, sast found -> ignored + TP
        method bad, sast not found -> FN
    """
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    total = 0
    ignored = 0

    # for each flaw found from SAST
    for filename, found_list in sast_flaws.items():
        # for each flaw found from SAST in the specified filename
        for found_from_tool in found_list:
            total += 1
            # check if the manifest flaw is related to SAST's flaw
            manifest_flaws_in_file = manifest_flaws.get(filename, [])
            if find_vuln_in_manifest_list(
                found_from_tool, manifest_flaws_in_file, cwe_tree
            ):
                # line and CWE are correct
                tp += 1
            else:
                # not found in manifest, but it may be a potential one
                pot_flaws_in_file = pot_flaws.get(filename, [])
                found = None
                for pot_flaw in pot_flaws_in_file:
                    tool_line = found_from_tool["line"]
                    pot_flaw_line = pot_flaw["line"]
                    if pot_flaw_line <= tool_line <= pot_flaw_line + 4:
                        found = pot_flaw
                if found is None:
                    # SAST found it, but it is not a potential one
                    fp += 1
                else:
                    # check if it is a potential one
                    match found["category"]:
                        case "negative":
                            fp += 1
                        case "positive":
                            ignored += 1

    # for each file and flaw in the manifest
    for filename, manifest_flaws_list in manifest_flaws.items():
        # filter by required CWE, if any
        if cwe is not None:
            curr_cwe = filename.split("_")[0][3:]
            if curr_cwe != cwe:
                continue

        # for each vulnerability found by SAST
        sast_vulns_in_file = sast_flaws.get(filename, [])
        for flaw in manifest_flaws_list:
            # if found it we already considered it
            if not find_vuln_in_manifest_list(flaw, sast_vulns_in_file, cwe_tree):
                fn += 1
                total += 1

    for filename, pot_flaws_list in pot_flaws.items():
        # filter by required CWE, if any
        if cwe is not None:
            curr_cwe = filename.split("_")[0][3:]
            if curr_cwe != cwe:
                continue

        # search flaw in sast flaws
        for pot_flaw in pot_flaws_list:
            if pot_flaw["category"] == "negative":
                sast_found_in_file = sast_flaws.get(filename, [])
                found = False  # check if the SAST found this flaw
                for el in sast_found_in_file:
                    # do not check by CWE since that flaw must NOT be found
                    el_line = el["line"]
                    pot_flaw_line = pot_flaw["line"]
                    if pot_flaw_line <= el_line <= pot_flaw_line + 4:
                        found = True
                # the SAST didn't find this flaw
                if not found:
                    tn += 1
                    total += 1

    p = tp + fp
    n = tn + fn

    retdict = {
        "false positive": fp,
        "true positive": tp,
        "false negative": fn,
        "true negative": tn,
        "accuracy": (tp + tn) / (p + n) if p + n > 0 else 0,
        "precision": tp / p if p > 0 else 0,
        "recall": tp / (fp + fn) if fp + fn > 0 else 0,
    }

    return retdict
