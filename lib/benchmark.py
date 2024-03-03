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


def are_cwe_related(cwe1, cwe2, cwe_tree):
    # TODO: check this
    if cwe1 in cwe_tree[cwe2] or cwe2 in cwe_tree[cwe1]:
        return True
    return False


def find_vuln_in_list(vuln, list, cwe_tree):
    for el in list:
        if vuln["line"] == el["line"]:
            if are_cwe_related(vuln["cwe"], el["cwe"], cwe_tree):
                return el
    return None


def confusion_matrix(pot_flaws, flaws, sast_data, cwe, cwe_tree):
    """
    For each vuln found by the SAST:
        If found in manifest:
            True positive
        Else:
            If found in our flaws file:
                If in method bad:
                    Ignore it
                Else:
                    False positive
            Else:
                False positive

    For each vuln found in manifest:
        If found in SAST:
            Ignore it (false positive, but we have already count it)
        Else:
            False negative

    Potential Flaws:
        cwe different -> skip
        cwe correct -> total++
        method good, sast found -> FP
        method bad, sast found -> ignored + TP
        method good, sast not found -> skip
        method bad, sast not found -> FN
        TN = total - (FP + TP + FN + ignored)
    """
    # FIXME: check count of positive and negative
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    total = 0
    ignored = 0

    for filename, found_list in sast_data.items():
        for found_from_tool in found_list:
            flaws_in_file = flaws.get(filename)
            if flaws_in_file is None:
                fp += 1
            else:
                found_in_flaws = find_vuln_in_list(
                    found_from_tool, flaws_in_file, cwe_tree
                )
                if found_in_flaws is not None:
                    tp += 1
                else:
                    pot_flaws_in_file = pot_flaws.get(filename)
                    if pot_flaws_in_file is None:
                        continue
                    found_in_pot_flaws = find_vuln_in_list(
                        found_from_tool, pot_flaws_in_file, cwe_tree
                    )
                    if found_in_pot_flaws is not None:
                        if found_in_pot_flaws["category"] == "positive":
                            ignored += 1
                        else:
                            fp += 1
                    else:
                        fp += 1

    for filename, flaws_list in flaws.items():
        if cwe is not None:
            curr_cwe = filename.split("_")[0][3:]
            if curr_cwe != cwe:
                continue
        total += 1
        sast_vulns_in_file = sast_data.get(filename)
        if sast_vulns_in_file is None:
            fn += len(flaws_list)  # TODO: check this
            continue
        for flaw in flaws_list:
            # if found it we already considered it
            if not find_vuln_in_list(flaw, sast_vulns_in_file, cwe_tree):
                fn += 1

    for filename, pot_found_list in pot_flaws.items():
        if cwe is not None:
            curr_cwe = filename.split("_")[0][3:]
            if curr_cwe != cwe:
                continue
        total += len(pot_found_list)

    tn = total - (fp + tp + fn + ignored)

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
