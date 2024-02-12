import time
import os
import sys
import json
import output_parser as parser


def main():

    # Read cmd line args
    args_len = len(sys.argv)
    if args_len < 2:
        print("You have to specify either -java or -js")
        exit()
    match (sys.argv[1]):
        case "-java":
            java = True
            dir = "~/.Juliet/src/testcases/CWE89_SQL_Injection/s03"
        case "-js":
            java = False
            dir = "~/.juice-shop"
        case _:
            print("You have to specify either -java or -js")
            exit()
    language = "java" if java else "js"
    outdir = f"out/{language}"

    # Create output directories
    os.makedirs(outdir, exist_ok=True)

    ### SEMGREP ###
    # Execute
    semgrep_time_start = time.perf_counter()
    os.system(f"semgrep scan {dir} --json -o {outdir}/semgrep.json")
    semgrep_time_end = time.perf_counter()
    semgrep_time = semgrep_time_end - semgrep_time_start
    # Parse and filter
    semgrep_data = parser.filter_semgrep_data(f"{outdir}/semgrep.json")
    with open(f"{outdir}/semgrep_filtered.json", "w") as f:
        f.write(json.dumps(semgrep_data, indent=4))
    # Aggregate
    semgrep_aggr = parser.aggregate_cwe(semgrep_data)
    with open(f"{outdir}/semgrep_vulns.json", "w") as f:
        f.write(json.dumps(semgrep_aggr, indent=4, sort_keys=True))

    ### BEARER ###
    # Execute
    bearer_time_start = time.perf_counter()
    os.system(f"bearer --force --format=json --output={outdir}/bearer.json scan {dir}")
    bearer_time_end = time.perf_counter()
    bearer_time = bearer_time_end - bearer_time_start
    # Parse and filter
    bearer_data = parser.filter_bearer_data(f"{outdir}/bearer.json")
    with open(f"{outdir}/bearer_filtered.json", "w") as f:
        f.write(json.dumps(bearer_data, indent=4))
    # Aggregate
    bearer_aggr = parser.aggregate_cwe(bearer_data)
    with open(f"{outdir}/bearer_vulns.json", "w") as f:
        f.write(json.dumps(bearer_aggr, indent=4, sort_keys=True))

    ### HORUSEC ###
    # Execute
    horusec_time_start = time.perf_counter()
    os.system(f"horusec start -p {dir} -D -O {outdir}/horusec.json -o json")
    horusec_time_end = time.perf_counter()
    horusec_time = horusec_time_end - horusec_time_start
    # Parse and filter
    horusec_data = parser.filter_horusec_data(f"{outdir}/horusec.json")
    with open(f"{outdir}/horusec_filtered.json", "w") as f:
        f.write(json.dumps(horusec_data, indent=4))
    # Aggregate
    horusec_aggr = parser.aggregate_cwe(horusec_data)
    with open(f"{outdir}/horusec_vulns.json", "w") as f:
        f.write(json.dumps(horusec_aggr, indent=4, sort_keys=True))

    # Print results
    print("\n\n\nRESULTS:\n")
    print(f"Semgrep took {semgrep_time:.3f} seconds")
    print(f"Bearer took {bearer_time:.3f} seconds")
    print(f"Horusec took {horusec_time:.3f} seconds")
    print()


if __name__ == "__main__":
    main()
