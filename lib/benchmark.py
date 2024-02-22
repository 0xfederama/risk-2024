import json
import time
import os
import lib.output_parser as output_parser

debug = False


def get_cmd(tool, codedir, outdir):
    outfile = f"{outdir}/{tool}.json"
    # Get the command to run with the correct tool and test suite
    redirect = ""
    if not debug:
        redirect = f" &> /tmp/{tool}_run_{int(time.time())}.log"
    command = ""
    match tool:
        case "semgrep":
            command = f"semgrep scan {codedir} --json -o {outfile}"
        case "bearer":
            command = f"bearer scan {codedir} --force --format=json --output={outfile}"
        case "horusec":
            command = f"horusec start -p {codedir} -D -O {outfile} -o json"
    return command + redirect, outfile


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


def find_flaw(filename, found_elem, flaws):
    if filename not in flaws:  # case 2
        return None

    for found_in_flaw in flaws[filename]:
        if int(found_in_flaw["line"]) == int(found_elem["line"]): 
            return found_in_flaw

    return None


def confusion_matrix(flaws, filtered_data, cwe=None):
    """
    flaws: positive (method bad), negative (method good)
    1) found in tool, found in flaws:
        if cwe tool != cwe flaws -> FP
        if flaws negative -> FP
        if flaws positive -> TP
    2) found in tool, not found in flaws:
        FP
    3) not found in tool, found in flaws:
        if flaws positive -> FN
        if flaws negative -> TN


    foreach vuln in tool_filtered:
        1) found in flaws:
            if cwe tool != cwe flaws -> FP++
            if flaws negative -> FP++
            if flaws positive -> TP++
        2) not found in flaws:
            FP++

    foreach flaw in flaws:
        1) found in filtered:
            skip
        3) not found in filtered:
            if flaw negative -> TN++
            if flaw positive -> FN++
    """
    fp = 0
    tp = 0
    fn = 0
    tn = 0

    for filename, found_list in filtered_data.items():
        for found_from_tool in found_list:
            # search if the vuln found by the tool is in the flaws
            flaws_found = find_flaw(filename, found_from_tool, flaws)
            # case 2, not found filename or not same line
            if flaws_found is None:
                fp += 1
                continue
            # case 1, same filename and same line
            if flaws_found['cwe'] != found_from_tool["cwe"]:  # different CWE
                fp += 1
                continue

            # case 1, same filename, same line, same CWE
            if flaws_found["category"] == "negative":
                fp += 1
            else:
                tp += 1
    
    for filename, flaw_list in flaws.items():
        if cwe is not None and f"CWE{cwe}" not in filename:
            continue
        for fl in flaw_list:
            found_from_tool = find_flaw(filename, fl, filtered_data)
            # case 1, found in filtered_data
            if found_from_tool is not None:
                continue
            # case 3, not found in filtered_data
            if fl["category"] == "negative":
                tn += 1
            else:
                fn += 1

    p = tp + fp
    n = tn + fn

    retdict = {
        "false positive": fp,
        "true positive": tp,
        "false negative": fn,
        "true negative": tn,
        "accuracy": (tp + tn) / (p + n),
        "precision": tp / p,
        "recall": tp / (fp + fn),
    }

    return retdict
