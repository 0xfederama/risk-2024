Run semgrep with
```
semgrep scan ../Juliet/src/testcases/CWE89_SQL_Injection/s03 --json > semgrep_output.json
```

Run bearer with
```
bearer --format=json --output=./bearer_output.json scan ../Juliet/src/testcases/CWE89_SQL_Injection/s03
```