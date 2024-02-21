import time
import os
import json
import argparse
import output_parser

debug = True


class Config:
    # Class representing the configuration settings for the project.
    CONFIG_FILE = "./config.json"
    config = {}
    tool = None
    lang = None

    def __init__(self):
        # initialize argument parser and add options
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--tool",
            "-t",
            help="The tool to use",
            choices=["semgrep", "bearer", "horusec"],
        )
        parser.add_argument(
            "--lang",
            "-l",
            help="The language of the Juliet test suite",
            choices=["java", "cpp", "csharp"],
        )
        args = parser.parse_args()
        self.tool = args.tool
        self.lang = args.lang

        with open(self.CONFIG_FILE, "r") as f:
            self.config = json.load(f)

    def get_juliet_path_by_lang(self, lang):
        # Get the path for the Juliet test suite based on the specified language.
        return self.config[f"juliet_{lang}_path"]


def cmd(tool, codedir, outfile):
    # Get the command to run with the correct tool and test suite
    redirect = ""
    if not debug:
        redirect = f" &> /tmp/{tool}_run_{int(time.time())}.log"
    match tool:
        case "semgrep":
            return f"semgrep scan {codedir} --json -o {outfile}" + redirect
        case "bearer":
            return (
                f"bearer scan {codedir} --force --format=json --output={outfile}"
                + redirect
            )
        case "horusec":
            return f"horusec start -p {codedir} -D -O {outfile} -o json" + redirect


def run_tool(outdir, tool, codedir):
    outfile = f"{outdir}/{tool}.json"
    # Execute tool
    time_start = time.perf_counter()
    os.system(cmd(tool, codedir, outfile))
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


tool_support = {
    "java": ["semgrep", "horusec", "bearer"],
    "cpp": ["semgrep"],
    "csharp": ["semgrep", "horusec"],
}


def run_horusec(outdir, tool, codedir):
    total_time = 0
    total_filtered_data = []
    total_aggr_data = {"total": 0, "vulns": {}}
    print(f"{codedir}/src/testcases/")

    for dir in os.listdir(f"{codedir}/src/testcases/"):
        dir = f"{codedir}/src/testcases/{dir}"
        if "CWE" not in dir:
            continue

        # Run on the directory
        print("RUNNING ON DIR:", dir)
        run_time, run_filtered_data, run_aggr_data = run_tool(outdir, tool, dir)
        total_time += run_time
        total_filtered_data += run_filtered_data
        total_aggr_data["total"] += run_aggr_data["total"]
        for cwe, cwe_count in run_aggr_data["vulns"].items():
            total_aggr_data["vulns"][cwe] = (
                total_aggr_data["vulns"].get(cwe, 0) + cwe_count
            )

    # Override previous json outputs
    with open(f"{outdir}/{tool}_filtered.json", "w") as f:
        f.write(json.dumps(total_filtered_data, indent=4))
    with open(f"{outdir}/{tool}_vulns.json", "w") as f:
        f.write(json.dumps(total_aggr_data, indent=4, sort_keys=True))

    return total_time, total_filtered_data, total_aggr_data


def main():
    # Define/parse arguments and get filepaths of test suites
    config = Config()

    # Check if the tool supports the specified language
    if config.tool is not None and config.lang is not None:
        if config.tool not in tool_support[config.lang]:
            print(f"Tool {config.tool} does not support {config.lang}")
            exit()

    tools = ["semgrep", "bearer", "horusec"] if config.tool is None else [config.tool]
    langs = ["java", "cpp", "csharp"] if config.lang is None else [config.lang]

    # If running on everything, backup old directory
    if config.tool is None and config.lang is None:
        os.system("rm -rf out.bak")
        os.rename("out", "out.bak")

    # Print results
    results = []
    for lang in langs:
        supported_tools = tool_support[lang]
        for tool in tools:
            if tool not in supported_tools:
                continue

            # Create output directories
            outdir = f"out/{lang}/{tool}"
            os.makedirs(outdir, exist_ok=True)

            # Run test
            codedir = f"{config.get_juliet_path_by_lang(lang)}"
            print(f"Running {tool} on {lang}, directory {codedir}")
            if tool == "horusec" and "CWE" not in codedir:
                t, filtered_data, aggr_data = run_horusec(outdir, tool, codedir)
            else:
                t, filtered_data, aggr_data = run_tool(outdir, tool, codedir)
            results.append((tool, lang, t))

    # Print results
    print("\nRESULTS:\n")
    for tool, lang, t in results:
        print(f"{tool.capitalize()} on {lang} took {t:.3f} seconds")


if __name__ == "__main__":
    main()
