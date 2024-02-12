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


if __name__ == "__main__":
    with open("horusec.json", "r") as f:
        data = json.load(f)
        show_dict_structure(data, "")
