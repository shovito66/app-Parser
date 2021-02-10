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
# print(files)

for file in files:
    # Opening JSON file
    # f = open('upay_1.4.2.json',)
    f = open(file)
    data = json.load(f)

    appName = data['app_name']
    appType = data['app_type']
    pkgName = data['package_name']
    avgCVSSscore = data['average_cvss']
    detectedTrackers = data['trackers']['detected_trackers']
    totalTrackers = (data['trackers']['total_trackers'])
    # print(detectedTrackers)
    AppSecurityScore = data['security_score']
    playStoreURL = data["playstore_details"]["appId"]
    privacyPolicyLink = data["playstore_details"]["privacyPolicy"]
    # AppInforMation
    max_sdk = data['max_sdk']
    min_sdk = data['min_sdk']

    # ------Permission------
    statusPermission = {
        "normal": [],
        "dangerous": [],
        "unknown": [],
        "signature": [],
    }

    permissionData = data['permissions']

    for key, value in permissionData.items():
        # print(value['status'])
        tempData = {
            "permission": key,
            "info": value["info"],
            "description": value["description"],
        }
        if value['status'] == "normal":
            statusPermission["normal"].append(tempData)
        elif value['status'] == "dangerous":
            statusPermission["dangerous"].append(tempData)
        elif value['status'] == "signature":
            statusPermission["signature"].append(tempData)
        else:
            statusPermission["unknown"].append(tempData)

        # print(tempData['permission'])
    totalNormalStatus = len(statusPermission["normal"])
    totalDangerousStatus = len(statusPermission["dangerous"])
    totalSignatureStatus = len(statusPermission["signature"])
    totalUnknownStatus = len(statusPermission["unknown"])
    # ----------------------------------------------------------------------

    # ----------------APKID ANALYSIS------------------------------
    apkidData = data["apkid"]
    antiDebugCodeList = []
    antiVMCodeList = []
    for key, value in apkidData.items():
        antiDebugCodeList = value["anti_debug"]
        antiVMCodeList = value["anti_vm"]
    # ----------------------------------------------------------------------

    # ----------------MANIFEST ANALYSIS-------------------------------------
    mainfestData = {
        "high": [],
        "medium": [],
    }
    for item in data["manifest_analysis"]:
        tempData = {
            "desc": item["desc"],
            "title": item["title"],
            "issue": item["name"],
        }

        if item["stat"] == "high":
            mainfestData["high"].append(tempData)
        elif item["stat"] == "medium":
            mainfestData["medium"].append(tempData)
    # ----------------------------------------------------------------------

    # ----------------CODE ANALYSIS-------------------------------------
    codeData = data["code_analysis"]
    severityFileCount = {
        "info": 0,
        "high": 0,
        "good": 0,
        "warning": 0,
        "secure": 0,
    }
    for key, value in codeData.items():
        severityFileCount[value["metadata"]["severity"]
                          ] = severityFileCount[value["metadata"]["severity"]] + len(value["files"])
    # print(severityFileCount)
    # ----------------------------------------------------------------------

    # ---------------SHARED LIBRARY BINARY ANALYSIS-------------------------------------
    """sharedLibData = data["binary_analysis"] 
    for item in data["binary_analysis"]:
        print(item) """
    # ----------------------------------------------------------------------

    # ---------------DOMAIN MALEWARE CHECK-------------------------------------
    domainStatus = {
        "good": [],
        "bad": [],
    }

    for key, value in data["domains"].items():
        if value["bad"] == "no":
            domainStatus["good"].append(key)
        else:
            domainStatus["bad"].append(key)
    # print(domainStatus)

    # ----------------------------------------------------------------------

    # --------------------EMAIL------------------------
    emails = []
    for item in data["emails"]:
        emails = item["emails"]

    # --------------------URLS------------------------
    urlStatus = {
        "https": [],
        "http": [],
        "local": [],
        "others": [],
    }
    httpsPattern = re.compile("https")
    httpPattern = re.compile("http")
    localPattern = re.compile("localhost|127.0.0.1")

    for item in data["urls"]:
        for url in item["urls"]:
            if httpsPattern.search(url):
                urlStatus["https"].append(url)
            elif httpPattern.search(url):
                urlStatus["http"].append(url)
            elif localPattern.search(url):
                urlStatus["local"].append(url)
            else:
                urlStatus["others"].append(url)
    # print(urlStatus)

    print("\n\n--------------------RESULT ANALYSIS of APP:{}--------------------------".format(appName))

    print("appName:{}, \tPlayStore URL: {} \tPrivacyPolicy Link: {} \tappType:{}, \tpkgName:{}, \tavgCVSSscore:{}, \nTrackers Detection:{}/{} \nMax SDK:{} \tMIN SDK:{}"
          .format(appName, playStoreURL, privacyPolicyLink, appType, pkgName, avgCVSSscore, detectedTrackers, totalTrackers, max_sdk, min_sdk))

    print("\n-----PERMISSION ANALYSIS------\nNormal:{} \tdangerous:{} \tsignature:{} \tunknown:{} ".format(
        totalNormalStatus, totalDangerousStatus, totalSignatureStatus, totalUnknownStatus))

    print("antiDebugCodeList Length:{}  \tantiVMCodeList Length:{}".format(
        len(antiDebugCodeList), len(antiVMCodeList)))

    print("\n----MAINFEST ANALYSIS---- \nHigh Issue:{} \tMedium Issue:{}\t".format(
        len(mainfestData["high"]), len(mainfestData["medium"])))

    print("\n----CODE ANALYSIS---- \tinfo:{} \thigh:{} \twarning:{} \tsecure:{}\t".format(
        severityFileCount["info"], severityFileCount["high"], severityFileCount["warning"], severityFileCount["secure"]))

    print("\n----DOMAIN MALEWARE ANALYSIS---- \tGood:{} \tBad:{}".format(
        len(domainStatus["good"]), len(domainStatus["bad"])))
    print("\n----EMAILS:{}".format(emails))

    print("\n----URL ANALYSIS---- \thttps:{},\t http:{},\t local:{},\tOther:{}".format(
        len(urlStatus["https"]), len(urlStatus["http"]), len(urlStatus["local"]), len(urlStatus["others"])))

    # Closing file
    f.close()
    print("\n---------------------------------------------------------------------------------------------\n---------------------------------------------------------------------------------------------")
