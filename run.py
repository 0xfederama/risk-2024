import os
import json
import time
import lib.config as configs
import lib.benchmark as benchmark

debug = False

tool_support = {
    "java": ["semgrep", "snyk", "horusec"],
    "csharp": ["semgrep", "snyk", "horusec"],
    "cpp": ["semgrep", "snyk", "flawfinder"],
}

all_tools = ["semgrep", "snyk", "horusec", "flawfinder"]
all_langs = ["java", "csharp", "cpp"]


def run_tests(config, tools, langs):
    # If running on everything, backup old directory
    if config.tool is None and config.lang is None and os.path.exists("out"):
        os.rename("out", f"out_{int(time.time())}")

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
            results.append((tool, lang, elapsed_time))

    # Print results
    print("\nRESULTS:\n")
    for tool, lang, t in results:
        print(f"{tool.capitalize()} on {lang} took {t:.3f} seconds")


def create_confusion_matrix(tools, langs, cwe=None):
    for lang_dir in os.listdir("out"):
        if lang_dir not in langs:
            continue

        # Open Juliet flaws files for current language
        flaws = {}
        with open(f"util/juliet_{lang_dir}_flaws.json", "r") as f:
            flaws = json.load(f)

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
                    confmat = benchmark.confusion_matrix(flaws, filtered_data, cwe=cwe)
                    with open(
                        f"out/{lang_dir}/{tool_dir}/{tool_dir}_conf_mat.json", "w"
                    ) as f:
                        f.write(json.dumps(confmat, indent=4))


def main():
    # Define/parse arguments and get tools and languages
    config = configs.Config()

    # Check if the tool supports the specified language
    if config.tool is not None and config.lang is not None:
        if config.tool not in tool_support[config.lang]:
            print(f"Tool {config.tool} does not support {config.lang}")
            exit()

    tools = all_tools if config.tool is None else [config.tool]
    langs = all_langs if config.lang is None else [config.lang]

    print(f"Running on tools {str(tools)} with languages {str(langs)}")

    if not config.skip_tests:
        run_tests(config, tools, langs)
        print()
    else:
        print("\nSkipping tests")

    if not config.skip_cm:
        create_confusion_matrix(tools, langs, cwe=89)
        print()
    else:
        print("\nSkipping confusion matrix creation")


if __name__ == "__main__":
    main()
