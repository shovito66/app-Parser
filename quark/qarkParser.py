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

print(files)

for file in files:
    # Opening JSON file
    print("Current File:{}".format(file))
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



    '''
    # Structure of nestedDictonary
    {
        categorySet-->key ,
        value:{key->severitySet, value:[]}
    }
    '''

    # nestedDictonary = dict.fromkeys(
    #     categorySet, dict(dict.fromkeys(severitySet)))
    
    # for key, val in nestedDictonary.items():
    #     for k in val:
    #         nestedDictonary[key][k] = []
    # print(nestedDictonary)
    
    #---------------------------NEWLY ADDED--------------------#
    severityData = dict.fromkeys(severitySet)
    categoryData = dict.fromkeys(categorySet)
    for key in severityData:
        severityData[key]= []
    for key in categoryData:
        categoryData[key]= []

    for item in data:
        #---------------------------NEWLY ADDED--------------------#
        sData = {
            "category":item["severity"].lower(),
            "name":item["name"],
        }
        cData = {
            "severity":item["severity"].lower(),
            "name":item["name"],
        }
        severityData[item["severity"].lower()].append(sData) #new
        categoryData[item["category"].lower()].append(cData)
        #-------------------------------------------------
        # nestedDictonary[item["category"].lower()][item["severity"].lower()].append(item["name"])  #not working
    
    
    
    
    print("\n\n-------------APP PKG NAME:{}-------------".format(pkgName))
   #---------------------------NEWLY ADDED--------------------#
    print("--------------Result based on SEVIRITY--------------")
    for key in severityData:
        # print(key, '->',len( severityData[key]))
        print("Sevirity:{}\t\tNo:{}".format(key,len( severityData[key])))
    
    print("--------------Result based on CATEGORY--------------")
    for key in categoryData:
        print("Category:{}\t\tNo:{}".format(key,len( categoryData[key])))
    #-----------------------------------------------------
    
    # for key, value in nestedDictonary.items():
    #     for k,v in value.items():
    #         c = c + len(v)
    #          # @@@@todo: need to modify this
    #         print("Category:{}\t\tSevirity:{}\t\tNo:{}".format(key,k,len(v)))
    
    # Closing file    
    f.close()
    print("\n---------------------------------------------------------------------------------------------\n---------------------------------------------------------------------------------------------")

