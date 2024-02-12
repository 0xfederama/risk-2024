import json


def show_dict_structure(data, spaces):
    if type(data) == dict:
        newspaces = spaces + "\t"
        for key, value in data.items():
            print(f"{spaces}Key: {key} type={type(value)}")
            if type(value) == dict:
                show_dict_structure(value, newspaces)
            elif type(value) == list and len(value) > 0:
                show_dict_structure(value[0], newspaces)


def filter_semgrep_data(filename):
    with open(filename, "r") as f:
        data = json.load(f)
        results = data["results"]
        filtered_results = []
        for res in results:
            path = res["path"]
            line = res["start"]["line"]
            cwe_titles = res["extra"]["metadata"]["cwe"]
            cwe_codes = [cwe.split(":")[0] for cwe in cwe_titles]
            cwe_str = " | ".join(cwe_codes)
            confidence = res["extra"]["metadata"]["confidence"]
            impact = res["extra"]["metadata"]["impact"]

            filtered_results.append(
                {
                    "cwe": cwe_str,
                    "path": path,
                    "line": line,
                    "confidence": confidence,
                    "impact": impact,
                }
            )
        return filtered_results


def filter_bearer_data(filename):
    with open(filename, "r") as f:
        data = json.load(f)
        filtered_results = []
        for key, value in data.items():
            for elem in value:
                path = elem["full_filename"]
                line = elem["line_number"]
                cwe_titles = elem["cwe_ids"]
                cwe_str = " | ".join(cwe_titles)
                confidence = ""
                impact = key

                filtered_results.append(
                    {
                        "cwe": cwe_str,
                        "path": path,
                        "line": line,
                        "confidence": confidence,
                        "impact": impact,
                    }
                )
        return filtered_results


def aggregate_cwe(data):
    """
    example format of the input data
    {
        "cwe": cwe_str,
        "path": path,
        "line": line,
        "confidence": confidence,
        "impact": impact,
    }
    """
    res = dict()
    for elem in data:
        cwe = str(elem["cwe"])
        cwe = cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
        if cwe not in res:
            res[cwe] = 0

        res[cwe] += 1

    return res
