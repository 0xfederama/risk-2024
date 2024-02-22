import os
import lib.config as configs
import lib.benchmark as benchmark

debug = True

tool_support = {
    "java": ["semgrep", "horusec", "bearer"],
    "cpp": ["semgrep"],
    "csharp": ["semgrep", "horusec"],
}


def main():
    # Define/parse arguments and get filepaths of test suites
    config = configs.Config()

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
            codedir = f"{config.get_juliet_path(lang)}"
            print(f"Running {tool} on {lang}, directory {codedir}")
            time, filtered_data, aggr_data = benchmark.run(
                outdir=outdir, tool=tool, codedir=codedir, set_debug=debug
            )
            results.append((tool, lang, time))

    # Print results
    print("\nRESULTS:\n")
    for tool, lang, t in results:
        print(f"{tool.capitalize()} on {lang} took {t:.3f} seconds")


if __name__ == "__main__":
    main()
