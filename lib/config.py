import argparse
import json


class Config:
    # Class representing the configuration settings for the project.
    CONFIG_FILE = "./config.json"
    config = {}
    tool = None
    lang = None
    skip_cm = False
    skip_tests = False

    def __init__(self):
        # initialize argument parser and add options
        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--tool",
            "-t",
            help="The tool to use",
            choices=["semgrep", "horusec", "snyk", "flawfinder"],
        )
        parser.add_argument(
            "--lang",
            "-l",
            help="The language of the Juliet test suite",
            choices=["java", "cpp", "csharp"],
        )
        parser.add_argument(
            "--skip-cm", help="Skip confusion matrix creation", action="store_true"
        )
        parser.add_argument("--skip-tests", help="Skip tests run", action="store_true")
        args = parser.parse_args()
        self.tool = args.tool
        self.lang = args.lang
        self.skip_cm = args.skip_cm
        self.skip_tests = args.skip_tests

        with open(self.CONFIG_FILE, "r") as f:
            self.config = json.load(f)

    def get_juliet_path(self, lang):
        # Get the path for the Juliet test suite based on the specified language.
        return self.config[f"juliet_{lang}_path"]
