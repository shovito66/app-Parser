import json
import re
import os

newPath = "./"  # need to modify to point the directory where json files are
# newPath = "../../../data/csv/odi/"


def create_dir(path):
    if os.path.isdir(path):
        print("Already exist")
    else:
        os.mkdir(path)
        print("Directory created")


create_dir(newPath)
files = [file for file in os.listdir(newPath) if 'json' in file]



for file in files:
    # Opening JSON file
    
    f = open(file) 
    # f = open('MTB (2.0.3)-Qark-Report.json',)
    data = json.load(f)
    # print(data[923]["apk_exploit_dict"])

    pkgName = next((item for item in data if item.get("apk_exploit_dict") !=
                    None and item["apk_exploit_dict"].get("package_name")), None)["apk_exploit_dict"]["package_name"]

    severitySet = set()
    categorySet = set()
    for item in data:
        categorySet.add(item["category"].lower())
        severitySet.add(item["severity"].lower())

    nestedDictonary = dict.fromkeys(
        categorySet, dict(dict.fromkeys(severitySet, [])))
    '''
    # Structure of nestedDictonary
    {
        categorySet-->key ,
        value:{key->severitySet, value:[]}
    }
    '''
    # print(nestedDictonary)
    

    for item in data:
        nestedDictonary[item["category"].lower()][item["severity"].lower()].append(item["name"])

    print("\n\n-------------APP PKG NAME:{}-------------".format(pkgName))
    for key, value in nestedDictonary.items():
        for k,v in value.items():
             # @@@@todo: need to modify this
            print("Category:{}\t\tSevirity:{}\t\tNo:{}".format(key,k,len(v)))
    
    # Closing file
    f.close()
    print("\n---------------------------------------------------------------------------------------------\n---------------------------------------------------------------------------------------------")

