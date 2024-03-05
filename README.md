# ICT Risk Assessment - SAST comparison

This repo contains the code we used to test various SASTs on different test suites, in order to test and compare the static analyzers.

## SASTs tested:
- [semgrep](https://github.com/semgrep/semgrep)
- [horusec](https://github.com/ZupIT/horusec), using `-D` (`--disable-docker`) to use the proprietary SAST on java and c#
- [snyk](https://snyk.io/product/snyk-code/)
- [flawfinder](https://github.com/david-a-wheeler/flawfinder)
- [cppcheck](https://cppcheck.sourceforge.io/)

## Test suites:
- [nist juliet](https://samate.nist.gov/SARD/test-suites/111) for java
- [nist juliet](https://samate.nist.gov/SARD/test-suites/110) for c#
- [nist juliet](https://samate.nist.gov/SARD/test-suites/112) for c/c++

## Tools and suites:
Tools | Java | C# | C/C++ |
--- | --- | --- | --- |
Semgrep | ✅ | ✅ | ✅ |
Snyk | ✅ | ✅ | ✅ |
Horusec | ✅ | ✅ | ⛔️ |
Flawfinder | ⛔️ | ⛔️ | ✅ |
Cppcheck | ⛔️ | ⛔️ | ✅ |

## Metrics:
- accuracy: $\frac{TP+TN}{TP+TN+FP+FN}$
- precision: $\frac{TP}{TP+FP}$
- recall: $\frac{TP}{FP+FN}$

## Run
Before running, you need to create a file `config.json` to specify the directories of the test suites:
```
{
    "juliet_java_path": "/absolute/path/to/java/juliet/",
    "juliet_cpp_path": "/absolute/path/to/cpp/juliet/",
    "juliet_csharp_path": "/absolute/path/to/csharp/juliet/"
}
```

## Usage:
```
usage: run.py [-h] [--tool {semgrep,horusec,snyk,flawfinder}] [--lang {java,cpp,csharp}] [--skip-cm]
              [--skip-tests]

options:
  -h, --help            show this help message and exit
  --tool {semgrep,horusec,snyk,flawfinder}, -t {semgrep,horusec,snyk,flawfinder}
                        The tool to use
  --lang {java,cpp,csharp}, -l {java,cpp,csharp}
                        The language of the Juliet test suite
  --skip-cm             Skip confusion matrix creation
  --skip-tests          Skip tests run
```

Without specifying any option, the command runs every tool on every possible test suite.

## Considerations
- In order to run snyk on cpp, the tool wants LF as the end of file in the files, so you need to modify the entire Juliet suite in C/C++ in order to replace CRLF with LF. To that, we used [https://github.com/t-regx/crlf](https://github.com/t-regx/crlf).
- In order to create the confusion matrix, we read if a specific CWE directory is specified. But if also the internal `s` directory is specified (like `CWE89_SQL_Injection/s01`), the tool creates the confusion matrix in a wrong way. Thus, don't put the `s` directory in the juliet path and test the tool only on the full Juliet path or on the CWE directories at most.