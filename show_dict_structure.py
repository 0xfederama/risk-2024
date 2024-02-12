import json
import sys


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
    # Read cmd line args
    if len(sys.argv) < 2:
        print("You have to specify the file")
        exit()
    filename = sys.argv[1]
    if not str(filename).endswith(".json"):
        print("File has to be a json file")
        exit()

    # Read file and print structure
    with open(filename, "r") as f:
        data = json.load(f)
        show_dict_structure(data, "")
