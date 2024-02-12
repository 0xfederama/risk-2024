import time
import os
import sys
import json
import output_parser as parser


def main():
    # read cmd line args
    args_len = len(sys.argv)
    if args_len < 2:
        print("You have to specify either -java or -js")
        exit()

    if sys.argv[1] == "-java":
        java = True
    elif sys.argv[1] == "-js":
        java = False
    else:
        print("You have to specify either -java or -js")
        exit()

    file = (
        "../Juliet/src/testcases/CWE89_SQL_Injection/s03" if java else "../juice-shop"
    )
    language = "java" if java else "js"
    outdir = f"out/{language}"

    # create output directories
    os.makedirs(outdir, exist_ok=True)

    print(f"Running SASTs on {language}")

    # semgrep
    semgrep_time_start = time.perf_counter()
    os.system(f"semgrep scan {file} --json > {outdir}/semgrep_output.json")
    semgrep_time_end = time.perf_counter()
    semgrep_time = semgrep_time_end - semgrep_time_start

    # bearer
    bearer_time_start = time.perf_counter()
    os.system(f"bearer --format=json --output={outdir}/bearer_output.json scan {file}")
    bearer_time_end = time.perf_counter()
    bearer_time = bearer_time_end - bearer_time_start

    # print results
    print("\n\n\nRESULTS:\n")
    print(f"Semgrep took {semgrep_time:.3f} seconds")
    print(f"Bearer took {bearer_time:.3f} seconds")
    print()

    # parse results
    semgrep_data = parser.filter_semgrep_data(f"{outdir}/semgrep_output.json")
    bearer_data = parser.filter_bearer_data(f"{outdir}/bearer_output.json")
    with open(f"{outdir}/semgrep_output_filtered.json", "w") as f:
        f.write(json.dumps(semgrep_data, indent=4))
    with open(f"{outdir}/bearer_output_filtered.json", "w") as f:
        f.write(json.dumps(bearer_data, indent=4))

    # aggregate results vulns
    semgrep_aggr = parser.aggregate_cwe(semgrep_data)
    bearer_aggr = parser.aggregate_cwe(bearer_data)
    with open(f"{outdir}/semgrep_cwes.json", "w") as f:
        f.write(json.dumps(semgrep_aggr, indent=4, sort_keys=True))
    with open(f"{outdir}/bearer_cwes.json", "w") as f:
        f.write(json.dumps(bearer_aggr, indent=4, sort_keys=True))


if __name__ == "__main__":
    main()
