import os
import json
import time
import lib.config as configs
import lib.benchmark as benchmark

debug = False

tool_support = {
    "java": ["semgrep", "snyk", "horusec"],
    "csharp": ["semgrep", "snyk", "horusec"],
    "cpp": ["semgrep", "snyk", "flawfinder", "cppcheck"],
}

all_tools = ["semgrep", "snyk", "horusec", "flawfinder", "cppcheck"]
all_langs = ["java", "csharp", "cpp"]


def run_tests(config, tools, langs):
    # If running on everything, ask to backup old directory
    if os.path.exists("out"):
        print(
            "An 'out' directory already exists here. "
            + "Do you want to do a backup? [y/N] ",
            end="",
        )
        answer = input()
        if answer == "Y" or answer == "y":
            t = int(time.time())
            print(f"Doing backup of old output directory to out_{t}\n")
            os.rename("out", f"out_{t}")
        elif answer == "N" or answer == "n" or answer == "":
            print("Skipping backup of output directory\n")
        else:
            print("Answer not expected")
            exit(1)

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
            codedir = f"{config.get_juliet_path(lang)}"
            print(f"Running {tool} on {lang}, directory {codedir}")
            elapsed_time, _, _ = benchmark.run(
                outdir=outdir, tool=tool, codedir=codedir, set_debug=debug
            )
            results.append({"tool": tool, "lang": lang, "time_sec": elapsed_time})

    times = []
    if os.path.exists("out/times.json"):
        with open("out/times.json", "r") as f:
            times = json.load(f)

    # Print and replace results
    print("\nRESULTS:")
    for res in results:
        tool = res["tool"]
        lang = res["lang"]
        sec = res["time_sec"]
        print(f"{tool.capitalize()} on {lang} took {sec:.3f} seconds")
        found = False
        for tm in times:
            if tool == tm["tool"] and lang == tm["lang"]:
                found = True
                tm["time_sec"] = sec
        if not found:
            times.append(res)

    with open("out/times.json", "w") as f:
        f.write(json.dumps(times, indent=4))


def create_confusion_matrix(config, tools, langs):
    # Read the cwe tree from file
    cwe_tree = {}
    with open("util/cwe_tree_full.json", "r") as f:
        cwe_tree = json.load(f)

    for lang_dir in os.listdir("out"):
        if lang_dir not in langs:
            continue

        # Open Juliet potential flaws file for current language
        pot_flaws = {}
        with open(f"util/pot_flaws_{lang_dir}.json", "r") as f:
            pot_flaws = json.load(f)

        # Get if we specified the CWE in the config.json file
        juliet_path = config.get_juliet_path(lang_dir)
        if "CWE" in juliet_path:
            cwe = juliet_path.split("_")[0].split("/")[-1][3:]
        else:
            cwe = None

        # For each tool build the confusion matrix
        for tool_dir in os.listdir(f"out/{lang_dir}"):
            if tool_dir not in tools:
                continue

            for outfile in os.listdir(f"out/{lang_dir}/{tool_dir}"):
                if "filtered" in outfile:
                    # Open filtered file and build the confusion matrix
                    filtered_data = {}
                    with open(f"out/{lang_dir}/{tool_dir}/{outfile}", "r") as f:
                        filtered_data = json.load(f)

                    # Compute confusion matrix and write to file in out dir
                    print(f"Creating confusion matrix on {tool_dir} and {lang_dir}")
                    confmat = benchmark.confusion_matrix(
                        pot_flaws_dict=pot_flaws,
                        sast_flaws_dict=filtered_data,
                        cwe=cwe,
                        cwe_tree=cwe_tree,
                    )
                    with open(
                        f"out/{lang_dir}/{tool_dir}/{tool_dir}_conf_mat.json", "w"
                    ) as f:
                        f.write(json.dumps(confmat, indent=4))


def main():
    # Define/parse arguments and get tools and languages
    config = configs.Config()
    if config.verbose:
        global debug
        debug = True

    # Check if the tool supports the specified language
    if config.tool is not None and config.lang is not None:
        if config.tool not in tool_support[config.lang]:
            print(f"Tool {config.tool} does not support {config.lang}")
            exit()

    tools = all_tools if config.tool is None else [config.tool]
    langs = all_langs if config.lang is None else [config.lang]

    print(f"Specified tools {str(tools)} and languages {str(langs)}")

    print()
    if not config.skip_tests:
        run_tests(config, tools, langs)
    else:
        print("Skipping tests")

    print()
    if not config.skip_cm:
        create_confusion_matrix(config, tools, langs)
    else:
        print("Skipping confusion matrix creation")


if __name__ == "__main__":
    main()
