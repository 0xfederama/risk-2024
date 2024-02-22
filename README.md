# ICT Risk Assessment - SAST comparison

This repo contains the code we used to test various SASTs on different test suites, in order to test and compare the static analyzers.

SASTs tested:
- [semgrep](https://github.com/semgrep/semgrep)
- [bearer](https://github.com/bearer/bearer)
- [horusec](https://github.com/ZupIT/horusec), using `-D` (`--disable-docker`) to use the proprietary SAST on java and c#

Test suites:
- [nist juliet](https://samate.nist.gov/SARD/test-suites/111) for java
- [nist juliet](https://samate.nist.gov/SARD/test-suites/110) for c#
- [nist juliet](https://samate.nist.gov/SARD/test-suites/112) for c/c++

## Run
Before running, you need to create a file `config.json` to specify the directories of the test suites:
```
{
    "juliet_java_path": "/absolute/path/to/java/juliet/",
    "juliet_cpp_path": "/absolute/path/to/cpp/juliet/",
    "juliet_csharp_path": "/absolute/path/to/csharp/juliet/"
}
```

Usage:
```
usage: run.py [-h] [--tool {semgrep,bearer,horusec}] [--lang {java,cpp,csharp}] [--skip-cm] [--skip-tests]

options:
  -h, --help            show this help message and exit
  --tool {semgrep,bearer,horusec}, -t {semgrep,bearer,horusec}
                        The tool to use
  --lang {java,cpp,csharp}, -l {java,cpp,csharp}
                        The language of the Juliet test suite
  --skip-cm             Skip confusion matrix creation
  --skip-tests          Skip tests run
```

Without specifying any option, the command runs every tool on every possible test suite.