import os
import time
import lib.config as configs
import lib.benchmark as benchmark

debug = True

tool_support = {
    "java": ["semgrep", "horusec", "bearer"],
    "cpp": ["semgrep"],
    "csharp": ["semgrep", "horusec"],
}

all_tools = ["semgrep", "bearer", "horusec"]
all_langs = ["java", "cpp", "csharp"]


def run_tests(config):
    # Check if the tool supports the specified language
    if config.tool is not None and config.lang is not None:
        if config.tool not in tool_support[config.lang]:
            print(f"Tool {config.tool} does not support {config.lang}")
            exit()

    tools = all_tools if config.tool is None else [config.tool]
    langs = all_langs if config.lang is None else [config.lang]

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


def create_confusion_matrix(config):
    pass


def main():
    # Define/parse arguments and get filepaths of test suites
    config = configs.Config()

    if not config.skip_tests:
        run_tests(config)
    else:
        print("Skipping tests")

    if not config.skip_cm:
        create_confusion_matrix(config)
    else:
        print("Skipping confusion matrix creation")


if __name__ == "__main__":
    main()
