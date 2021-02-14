import re

# define the name of the file to read from
filename = "MTB (2.0.3)-AndroBugs-Report.txt"
file = open(filename, 'r')

# read the content of the file opened
fileLines = file.readlines()

# line count start from 0
# remove spaces from left using lstrip
pkgName = fileLines[7].split(':')[1].lstrip()
minSDK = fileLines[10].split(':')[1].lstrip()


fileLines = fileLines[18:]
# print(len(fileLines))


riskLevelKeySet = set()
errorTypeKeySet = set()
dataUnsorteList = []


for line in fileLines:
    errorRiskLevel = re.search(r"\[([A-Za-z0-9_]+)\]", line)

    if errorRiskLevel:
        errorRiskLevel = errorRiskLevel.group(1).lower()
        line = line.split("]")[1].lstrip()
        removeList = re.findall(r"(<[#A-Za-z0-9_\s\,-]+>)", line)
        for i in removeList:
            line = line.replace(i, "").lstrip()

        text = line.find('Vector ID')
        errorType = line[text+10:-3].lstrip().lower()

        riskLevelKeySet.add(errorRiskLevel)
        errorTypeKeySet.add(errorType)

        errorDescription = line.split("(Vector")[0].lstrip().rstrip()

        # print(errorDescription)
        # print(errorType)
        # print(errorRiskLevel.lower())

        # tempData = {
        #     "errorRiskLevel": errorRiskLevel,
        #     "errorType": errorType,
        #     "errorDescription": errorDescription,
        # }
        dataUnsorteList.append({
            "errorRiskLevel": errorRiskLevel,
            "errorType": errorType,
            "errorDescription": errorDescription,
        })
        # tempData.clear()


nestedDataDictionary = dict.fromkeys(
    riskLevelKeySet, dict.fromkeys(errorTypeKeySet, []))

for item in dataUnsorteList:
    print(item)
    des = item["errorDescription"]
    risk = item["errorRiskLevel"]
    etype = item["errorType"]
    if des and risk and etype:
        nestedDataDictionary.get(risk).get(etype).append(des)

    # nestedDataDictionary[des][risk].append(etype)

print("Total Info Found:{}".format(len(dataUnsorteList)))
print("\n\n-------------APP PKG NAME:{}------------- \nMIN SDK:{}".format(pkgName,minSDK)) 

for key, value in nestedDataDictionary.items():
        for k,v in value.items():
            
            print("Risk:{}\tVectorID:{}\t\tErrorDescription:{}".format(key,k,v))
