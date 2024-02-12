# ICT Risk Assessment - SAST comparison

This repo contains the code we used to test various SASTs on different test suites, in order to test and compare the static analyzers.

Run with `python3 run.py -java` or `python3 run.py -js`.

SASTs tested:
- [semgrep](https://github.com/semgrep/semgrep)
- [bearer](https://github.com/bearer/bearer)
- [horusec](https://github.com/ZupIT/horusec), using `-D` (`--disable-docker`) to use the proprietary SAST on java and javascript

Test suites:
- [nist juliet](https://samate.nist.gov/SARD/test-suites/111) for java
- [owasp juice-shop](https://github.com/juice-shop/juice-shop) for javascript