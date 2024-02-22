import json
import os


class FilteredData:
    def __init__(self):
        self.data = {}

    def add(self, path, cwe, line, confidence, severity):
        filename = os.path.basename(path)
        self.data[filename] = self.data.get(filename, [])
        self.data[filename].append(
            {
                "cwe": cwe,
                "line": line,
                "confidence": confidence,
                "severity": severity,
            }
        )


def filter_semgrep_data(filename):
    with open(filename, "r") as f:
        data = json.load(f)
        results = data["results"]
        filtered_results = FilteredData()
        for res in results:
            path = res["path"]
            line = res["start"]["line"]
            cwe_titles = res["extra"]["metadata"]["cwe"]
            if type(cwe_titles) == list:
                cwe_codes = [cwe.split(":")[0] for cwe in cwe_titles]
                cwe_str = " | ".join(cwe_codes)
            else:
                cwe_codes = cwe_titles.split(":")[0]
                cwe_str = cwe_codes
            confidence = res["extra"]["metadata"]["confidence"]
            severity = res["extra"]["metadata"]["impact"]

            filtered_results.add(
                path=path,
                cwe=cwe_str,
                line=line,
                confidence=confidence,
                severity=severity,
            )
        return filtered_results.data


def filter_bearer_data(filename):
    with open(filename, "r") as f:
        data = json.load(f)
        filtered_results = FilteredData()
        for key, value in data.items():
            for elem in value:
                path = elem["full_filename"]
                line = elem["line_number"]
                cwe_titles = elem["cwe_ids"]
                cwe_str = " | ".join(cwe_titles)
                confidence = ""
                severity = key

                filtered_results.add(
                    path=path,
                    cwe=cwe_str,
                    line=line,
                    confidence=confidence,
                    severity=severity,
                )
        return filtered_results.data


def filter_horusec_data(filename):
    rules = {}
    with open("./util/horusec_rules.json", "r") as f:
        rules = json.load(f)

    with open(filename, "r") as f:
        data = json.load(f)
        filtered_results = FilteredData()
        analysisVulnerabilities = data["analysisVulnerabilities"]
        if analysisVulnerabilities is None or analysisVulnerabilities == "null":
            analysisVulnerabilities = []

        for vuln in analysisVulnerabilities:
            vuln = vuln["vulnerabilities"]
            line = vuln["line"]
            path = vuln["file"]
            confidence = vuln["confidence"]
            severity = vuln["severity"]
            cwe_list = rules.get(vuln["rule_id"], [])
            for cwe in cwe_list:
                cwe_str = str(cwe)

                filtered_results.add(
                    path=path,
                    cwe=cwe_str,
                    line=line,
                    confidence=confidence,
                    severity=severity,
                )

        return filtered_results.data


def aggregate_cwe(data_to_aggregate):
    """
    example format of the input data
    {
        "filename": [
            {
                "cwe": cwe_str,
                "line": line,
                "confidence": confidence,
                "severity": severity
            },
            ...
        ]
    }
    """
    res = {}
    total_vulns = 0
    for _, data in data_to_aggregate.items():
        for elem in data:
            cwe = str(elem["cwe"])
            cwe = cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
            total_vulns += 1
            if cwe not in res:
                res[cwe] = 0

            res[cwe] += 1

    return {"vulns": res, "total": total_vulns}


def filter_data(tool, data):
    match tool:
        case "semgrep":
            return filter_semgrep_data(data)
        case "horusec":
            return filter_horusec_data(data)
        case "bearer":
            return filter_bearer_data(data)
        case _:
            print("Tool not supported")
            exit()
