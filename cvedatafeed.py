import os, sys
from os import listdir
from os.path import isfile, join
from urllib.parse import urlparse
from flask import Flask
from flask_pymongo import PyMongo
import requests
import logging
from datetime import datetime, timedelta, timezone
import datetime
import time
from zipfile import ZipFile
import shutil
import json
from threading import Thread
import threading
import _thread
import base64
import traceback

app = Flask(__name__)
app.config["MONGO_URI"] = os.environ.get('MONGODB_URI', "mongodb://127.0.0.1:27017/cvedata")
mongo = PyMongo(app)

env_loglevel = os.environ.get('LOG_LEVEL', "INFO")
if env_loglevel == "ERROR":
	loglevel = logging.ERROR
elif env_loglevel == "DEBUG":
	loglevel = logging.DEBUG
else:
	loglevel = logging.INFO

env_logfile = os.environ.get('LOG_FILE', False)
if env_logfile:
	loghandler = [ logging.FileHandler("debug.log"), logging.StreamHandler()]
else:
	loghandler = [ logging.StreamHandler()]

logging.basicConfig(
    level=loglevel,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=loghandler
)

def saveConfigkey(configname, value):
	findrecord = {}
	findrecord['name'] = configname
	newvalues = { "$set": { "value": value } }
	mongo.db.configuration.update_one(findrecord, newvalues, upsert=True)

def getConfigkey(configname):
	findrecord = {}
	findrecord['name'] = configname
	result = mongo.db.configuration.find_one(findrecord)
	if result == None:
		return "0"
	else:
		return result['value']

def saveStatistic(statname, value):
	findrecord = {}
	findrecord['statname'] = statname
	newvalues = { "$set": { "value": value } }
	mongo.db.statistics.update_one(findrecord, newvalues, upsert=True)

def getStatistic(statname):
	findrecord = {}
	findrecord['statname'] = statname
	result = mongo.db.statistics.find_one(findrecord)
	if result == None:
		return "0"
	else:
		return result['value']

def getCveList(nameid):
	findrecord = {}
	findrecord['nameid'] = nameid
	result = mongo.db.cvelists.find_one(findrecord)
	if result == None:
		return "0"
	else:
		return result['cves']

def updateVulTypeCollection(cveid, vultype):
	try:
		if vultype[0] != "None":
			for t in vultype:
				findrecord = {}
				findrecord['vultype'] = t
				if mongo.db.vultypes.count_documents(findrecord) == 0:
					findrecord['cves'] = [cveid]
					findrecord['numberofcve'] = 1
					mongo.db.vultypes.insert_one(findrecord)
				else:
					newvalues = { "$addToSet": { "cves": cveid } }
					mongo.db.vultypes.update_one(findrecord, newvalues)
					newvalues = { "$inc": { "numberofcve": 1 } }
					mongo.db.vultypes.update_one(findrecord, newvalues)
	except Exception as e:
		logging.error("Exception in updateVulTypeCollection %s" % e)

def getCVEtitle(cvejson):
	fmvultype = ""
	for t in cvejson["vultype"]:
		if fmvultype != "":
			fmvultype = fmvultype + ", "
		fmvultype = fmvultype + t.replace("_", " ").replace("-", " ").replace("\\","").replace("/","").replace("..",":").strip().title()
	if len(cvejson["affected"]) == 0:
		strproduct = "Unknown"
	else:
		aff = cvejson["affected"][0]
		ar = aff.split(":")
		strproduct = "%s_%s" % (ar[1], ar[2])
		strproduct = strproduct.replace("_", " ").replace("-", " ").replace("\\","").replace("/","").replace("..",":").strip().title()
	cvetitle = "%s: %s vulnerability on %s" % (cvejson["CVEID"], fmvultype, strproduct)
	return cvetitle

def insertNewCVE(cvejson):
	try:
		cvetitle = getCVEtitle(cvejson)
		cvejson["title"] = cvetitle
		return mongo.db.cves.insert_one(cvejson).inserted_id
	except Exception as e:
		logging.error("Exception in insertNewCVE %s" % e)
		return -1

def replaceCVE(cveid, newcve):
	try:
		cvetitle = getCVEtitle(newcve)
		newcve["title"] = cvetitle
		findrecord = {}
		findrecord['CVEID'] = cveid
		return mongo.db.cves.replace_one(findrecord, newcve)
	except Exception as e:
		logging.error("Exception in replaceCVE %s" % e)
		return -1

def getCVE(cveid):
	findrecord = {}
	findrecord['CVEID'] = cveid
	result = mongo.db.cves.find_one(findrecord)
	if result == None:
		return 0
	else:
		return result

def checkCveExist(cveid):
	findrecord = {}
	findrecord['CVEID'] = cveid
	return mongo.db.cves.count_documents(findrecord)

# cpe 2.3 parser processing
def getCompressCpeStr(Cpestr):
	arrstr = Cpestr.replace("\\:", "..").split(':')
	if(len(arrstr) < 7 or arrstr[0] != 'cpe' or arrstr[1] != '2.3'):
		logging.error("Wrong format in getCompressCpeStr with %s" % Cpestr)
		return Cpestr
	else:
		version = arrstr[5]
		for i in range(6,len(arrstr)):
			if(arrstr[i]!='*'):
				version = version + '_' + arrstr[i]
			else:
				continue
		return "%s:%s:%s:%s" % (arrstr[2], arrstr[3], arrstr[4], version)

# method: del/add
def getNewScoreAvg(method, lstscore, curavg, numberofcve, jsoncve):
	keyscore = str(int(jsoncve["baseScore"]))
	if keyscore == "10":
		keyscore = "9"
	if keyscore in lstscore.keys():
		ototal = lstscore[keyscore]
		if method == "add":
			lstscore[keyscore] = ototal + 1
		elif method == "del":
			lstscore[keyscore] = ototal - 1
	else:
		if method == "add":
			lstscore[keyscore] = 1
	if method == "add":
		newavg = (curavg * numberofcve + jsoncve["baseScore"]) / (numberofcve + 1)
	elif method == "del":
		if (numberofcve - 1) == 0:
			newavg = 0
		else:
			newavg = (curavg * numberofcve - jsoncve["baseScore"]) / (numberofcve - 1)
	return {"scorestat": lstscore, "avgscore": newavg}

def getNewVultypeStat(method, curstat, jsoncve):
	lstvultype = ["dos", "code_execution", "memory_corruption", "sql_injection", "xss", "path_traversal", "bypass_something", "information_exposure", "privilege_escalation", "other"]
	vultype = jsoncve["vultype"]
	cveid = jsoncve["CVEID"]
	aid = cveid.split("-")
	year = int(aid[1])

	foundindex = -1
	existstat = {}
	for i in range(len(curstat)):
		if curstat[i]["year"] == year:
			foundindex = i
			existstat = curstat[i]
			break
	
	if foundindex == -1:
		newstat = {}
		newstat["year"] = year
		newstat["vuls"] = {}
		for vul in lstvultype:
			if vul in vultype:
				newstat["vuls"][vul] = 1
			else:
				newstat["vuls"][vul] = 0
		if method == "add":
			curstat.append(newstat)
	else:
		newstat = existstat.copy()
		for vul in vultype:
			if method == "add":
				newstat["vuls"][vul] = existstat["vuls"][vul] + 1
			elif method == "del":
				newstat["vuls"][vul] = existstat["vuls"][vul] - 1
		curstat[foundindex] = newstat
	
	return curstat
		
def addCveidtoVersion(versionstr, jsoncve):
	Cveid = jsoncve["CVEID"]
	findrecord = {}
	findrecord['versionid'] = versionstr
	if mongo.db.versions.count_documents(findrecord) == 0:
		#findrecord['cves'] = [Cveid]
		findrecord['numberofcve'] = 1
		keyscore = str(int(jsoncve["baseScore"]))
		findrecord['scorestat'] = {}
		findrecord['scorestat'][keyscore] = 1
		findrecord['avgscore'] = jsoncve["baseScore"]
		newstat = getNewVultypeStat("add", [], jsoncve)
		findrecord['vulstat'] = newstat
		mongo.db.versions.insert_one(findrecord)

		findlist = {}
		findlist["nameid"] = versionstr
		newlist = { "$set": { "cves": [Cveid] } }
		mongo.db.cvelists.update_one(findlist, newlist, upsert=True)
	else:
		cursor = mongo.db.versions.find_one(findrecord)
		newscore = getNewScoreAvg("add", cursor["scorestat"], cursor["avgscore"], cursor["numberofcve"], jsoncve)
		newstat = getNewVultypeStat("add", cursor["vulstat"], jsoncve)

		newvalues ={}
		#newvalues["$addToSet"] = { "cves": Cveid }
		newvalues["$inc"] = { "numberofcve": 1 }
		setstat = { "vulstat": newstat }
		newvalues["$set"] = {**newscore, **setstat}
		mongo.db.versions.update_one(findrecord, newvalues)

		newlist = {}
		newlist["$addToSet"] = { "cves": Cveid }
		findlist = {}
		findlist["nameid"] = versionstr
		mongo.db.cvelists.update_one(findlist, newlist)

def delCveidfromVersion(versionstr, jsoncve):
	Cveid = jsoncve["CVEID"]
	findrecord = {}
	findrecord['versionid'] = versionstr
	cursor = mongo.db.versions.find_one(findrecord)
	if cursor != None:
		newscore = getNewScoreAvg("del", cursor["scorestat"], cursor["avgscore"], cursor["numberofcve"], jsoncve)
		newstat = getNewVultypeStat("del", cursor["vulstat"], jsoncve)

		newvalues ={}
		newvalues["$inc"] = { "numberofcve": -1 }
		setstat = { "vulstat": newstat }
		#setcve = { "cves": newlst }
		#newvalues["$set"] = {**newscore, **setstat, **setcve}
		newvalues["$set"] = {**newscore, **setstat}
		mongo.db.versions.update_one(findrecord, newvalues)

		currentlst = getCveList(versionstr)
		newlst = list(set(currentlst) - set([Cveid]))
		newlist = {}
		newlist["$set"] = { "cves": newlst }
		findlist = {}
		findlist["nameid"] = versionstr
		mongo.db.cvelists.update_one(findlist, newlist)

def addCveidtoProduct(productstr, versionstr, jsoncve):
	Cveid = jsoncve["CVEID"]
	findrecord = {}
	findrecord['productid'] = productstr
	if mongo.db.products.count_documents(findrecord) == 0:
		#findrecord['cves'] = [Cveid]
		findrecord['versions'] = [versionstr]
		findrecord['numberofcve'] = 1
		keyscore = str(int(jsoncve["baseScore"]))
		findrecord['scorestat'] = {}
		findrecord['scorestat'][keyscore] = 1
		findrecord['avgscore'] = jsoncve["baseScore"]
		newstat = getNewVultypeStat("add", [], jsoncve)
		findrecord['vulstat'] = newstat
		mongo.db.products.insert_one(findrecord)

		findlist = {}
		findlist["nameid"] = productstr
		newlist = { "$set": { "cves": [Cveid] } }
		mongo.db.cvelists.update_one(findlist, newlist, upsert=True)
	else:
		cursor = mongo.db.products.find_one(findrecord)
		newscore = getNewScoreAvg("add", cursor["scorestat"], cursor["avgscore"], cursor["numberofcve"], jsoncve)
		newstat = getNewVultypeStat("add", cursor["vulstat"], jsoncve)

		newvalues ={}
		#setcve = { "cves": Cveid }
		setversion = { "versions": versionstr }
		#newvalues["$addToSet"] = {**setcve, **setversion}
		newvalues["$addToSet"] = {**setversion}
		newvalues["$inc"] = { "numberofcve": 1 }
		setstat = { "vulstat": newstat }
		newvalues["$set"] = {**newscore, **setstat}
		mongo.db.products.update_one(findrecord, newvalues)

		newlist = {}
		newlist["$addToSet"] = { "cves": Cveid }
		findlist = {}
		findlist["nameid"] = productstr
		mongo.db.cvelists.update_one(findlist, newlist)

def delCveidfromProduct(productstr, jsoncve):
	Cveid = jsoncve["CVEID"]
	findrecord = {}
	findrecord['productid'] = productstr
	cursor = mongo.db.products.find_one(findrecord)
	if cursor != None:
		newscore = getNewScoreAvg("del", cursor["scorestat"], cursor["avgscore"], cursor["numberofcve"], jsoncve)
		newstat = getNewVultypeStat("del", cursor["vulstat"], jsoncve)

		newvalues ={}
		newvalues["$inc"] = { "numberofcve": -1 }
		setstat = { "vulstat": newstat }
		#setcve = { "cves": newlst }
		#newvalues["$set"] = {**newscore, **setstat, **setcve}
		newvalues["$set"] = {**newscore, **setstat}
		mongo.db.products.update_one(findrecord, newvalues)

		currentlst = getCveList(productstr)
		newlst = list(set(currentlst) - set([Cveid]))
		newlist = {}
		newlist["$set"] = { "cves": newlst }
		findlist = {}
		findlist["nameid"] = productstr
		mongo.db.cvelists.update_one(findlist, newlist)

def addCveidtoVendor(vendorstr, productstr, jsoncve):
	Cveid = jsoncve["CVEID"]
	findrecord = {}
	findrecord['vendorid'] = vendorstr
	if mongo.db.vendors.count_documents(findrecord) == 0:
		#findrecord['cves'] = [Cveid]
		findrecord['products'] = [productstr]
		findrecord['numberofcve'] = 1
		keyscore = str(int(jsoncve["baseScore"]))
		findrecord['scorestat'] = {}
		findrecord['scorestat'][keyscore] = 1
		findrecord['avgscore'] = jsoncve["baseScore"]
		newstat = getNewVultypeStat("add", [], jsoncve)
		findrecord['vulstat'] = newstat
		mongo.db.vendors.insert_one(findrecord)

		findlist = {}
		findlist["nameid"] = vendorstr
		newlist = { "$set": { "cves": [Cveid] } }
		mongo.db.cvelists.update_one(findlist, newlist, upsert=True)
	else:
		cursor = mongo.db.vendors.find_one(findrecord)
		newscore = getNewScoreAvg("add", cursor["scorestat"], cursor["avgscore"], cursor["numberofcve"], jsoncve)
		newstat = getNewVultypeStat("add", cursor["vulstat"], jsoncve)

		newvalues ={}
		#newvalues["$addToSet"] = {**setcve, **setproduct}
		newvalues["$addToSet"] = { "products": productstr }
		newvalues["$inc"] = { "numberofcve": 1 }
		setstat = { "vulstat": newstat }
		newvalues["$set"] = {**newscore, **setstat}
		mongo.db.vendors.update_one(findrecord, newvalues)

		newlist = {}
		setcve = { "cves": Cveid }
		newlist["$addToSet"] = {**setcve}
		findlist = {}
		findlist["nameid"] = vendorstr
		mongo.db.cvelists.update_one(findlist, newlist)

def delCveidfromVendor(vendorstr, jsoncve):
	Cveid = jsoncve["CVEID"]
	findrecord = {}
	findrecord['vendorid'] = vendorstr
	cursor = mongo.db.vendors.find_one(findrecord)
	if cursor != None:
		newscore = getNewScoreAvg("del", cursor["scorestat"], cursor["avgscore"], cursor["numberofcve"], jsoncve)
		newstat = getNewVultypeStat("del", cursor["vulstat"], jsoncve)

		newvalues ={}
		newvalues["$inc"] = { "numberofcve": -1 }
		setstat = { "vulstat": newstat }
		#newvalues["$set"] = {**newscore, **setstat, **setcve}
		newvalues["$set"] = {**newscore, **setstat}
		mongo.db.vendors.update_one(findrecord, newvalues)

		currentlst = getCveList(vendorstr)
		newlst = list(set(currentlst) - set([Cveid]))
		newlist = {}
		newlist["$set"] = setcve = { "cves": newlst }
		findlist = {}
		findlist["nameid"] = vendorstr
		mongo.db.cvelists.update_one(findlist, newlist)

# recursive function
# return list compressed CpeStr
def getAllcpeUriFromConf(ConJson, retCpeUri):
	if type(ConJson) == dict:
		for k in ConJson.keys():
			if k == "cpe23Uri":
				retCpeUri.append(getCompressCpeStr(ConJson[k]))
				return retCpeUri
			else:
				retCpeUri = getAllcpeUriFromConf(ConJson[k], retCpeUri)
	elif type(ConJson) == list:
		for i in ConJson:
			retCpeUri = getAllcpeUriFromConf(i, retCpeUri)
	elif type(ConJson) == str or type(ConJson) == bool:
		pass
	else:
		logging.error("Wrong format getAllcpeUriFromConf %s" % ConJson)
	return retCpeUri

import re

def testFilter(typestr, arrfilter):
	cvefiles = [f for f in listdir("CVEData") if isfile(join("CVEData", f))]
	arr = []
	for cvefile in cvefiles:
		print("[+] %s" % cvefile)
		with open("CVEData/" + cvefile, 'r') as file:
			cvedata = [json.loads(line) for line in file]
		numcve = 0
		for cve in cvedata:
			try:
				numcve = numcve + 1
				if numcve == 2000:
					break
				if "Vulnerability Type(s)" in cve.keys():
					if typestr in cve["Vulnerability Type(s)"].lower():
						cvejs = getCVE(cve["CVE ID"])
						arr.append(cvejs["cve"]["description"]["description_data"][0]["value"].lower())
			except Exception as e:
				logging.error("Exception in getTypeFilter %s" % e)
				pass
	im = 0
	for a in arr:
		bfound = False
		for b in arrfilter:
			if len(re.findall(b,a))>0:
				bfound = True
				break
		if bfound:
			im = im + 1
		else:
			logging.info(a)
	logging.info("out: %d/%d" % (im, len(arr)))

def checkKeywordinDescription(desc, kws):
	bfound = False
	for kw in kws:
		if len(re.findall(kw, desc)) > 0:
			bfound = True
			break
	return bfound

#testFilter("exec code",[r"(code|command).*(execution|execute)", r"(execution|execute).*(code|command)"])
#out: 10552/10552
#testFilter("dos",[r"denial of service"])
#out: 8260/8260
#testFilter("overflow",[r"overflow", r"(restrict|crash|invalid|violat|corrupt).*(buffer|stack|heap|memory)", r"(buffer|stack|heap|memory).*(restrict|crash|invalid|violat|corrupt)"])
#out: 5242/5814
#memory corruption
#https://www.cvedetails.com/cwe-details/120/cwe.html
#https://www.cvedetails.com/cwe-details/119/cwe.html
#https://www.cvedetails.com/cwe-details/190/cwe.html
#testFilter("sql",[r"sql injection"])
#https://www.cvedetails.com/cwe-details/89/cwe.html
#testFilter("xss",[r"xss"])
#https://www.cvedetails.com/cwe-details/79/cwe.html
#Dir. Trav. 
#testFilter("dir. trav",[r"directory traversal"])
#https://www.cvedetails.com/cwe-details/22/cwe.html
#testFilter("bypass",[r"bypass"])
#testFilter("info",[r"man-in-the-middle"])
#https://www.cvedetails.com/cwe-details/200/cwe.html
#testFilter("priv",[r"(gain|escalat).*privil", r"privil.*(gain|escalat)"])
#out: 1910/1910
def getVulTypeFromCVE(cve):
	logging.info("Get Vul type of %s" % cve["CVEID"])
	try:
		cvedesc = cve["cve"]["description"]["description_data"][0]["value"].lower()
	except Exception:
		return ["None"]
	try:
		cvecwe = cve["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"].lower()
	except Exception:
		cvecwe = "None"
	vultype = []
	#code_execution
	if checkKeywordinDescription(cvedesc, [r"(code|command).*(execution|execute)", r"(execution|execute).*(code|command)"]):
		vultype.append("code_execution")
	#dos
	if checkKeywordinDescription(cvedesc, [r"denial of service"]):
		vultype.append("dos")
	#memory_corruption
	if cvecwe in ["cwe-119", "cwe-120", "cwe-190"]:
		vultype.append("memory_corruption")
	elif checkKeywordinDescription(cvedesc, [r"overflow", r"(restrict|crash|invalid|violat|corrupt).*(buffer|stack|heap|memory)", r"(buffer|stack|heap|memory).*(restrict|crash|invalid|violat|corrupt)"]):
		vultype.append("memory_corruption")
	#sql_injection
	if cvecwe == "cwe-89":
		vultype.append("sql_injection")
	#xss
	if cvecwe == "cwe-79":
		vultype.append("xss")
	#path_traversal
	if cvecwe == "cwe-22":
		vultype.append("path_traversal")
	elif checkKeywordinDescription(cvedesc, [r"directory traversal"]):
		vultype.append("path_traversal")
	#bypass_something
	if checkKeywordinDescription(cvedesc, [r"bypass"]):
		vultype.append("bypass_something")
	#information_exposure
	if cvecwe == "cwe-200":
		vultype.append("information_exposure")
	elif checkKeywordinDescription(cvedesc, [r"man-in-the-middle"]):
		vultype.append("information_exposure")
	#privilege_escalation
	if checkKeywordinDescription(cvedesc, [r"(gain|escalat).*privil", r"privil.*(gain|escalat)"]):
		vultype.append("privilege_escalation")
	if len(vultype) == 0:
		vultype.append("other")
	logging.info("Vultype is %s" % vultype)
	return vultype

# Main function in convert cve json to mongodb
# return integer: number of cve imported, return -1 if error
def importCVEFromJsonfile(JsonfilePath):
	logging.info("importCVEFromJsonfile start with file %s" % JsonfilePath)
	if not os.path.isfile(JsonfilePath):
		logging.error("File %s is not exist" % JsonfilePath)
		return -1
	# read file to json
	with open(JsonfilePath, encoding="utf8") as f:
		nvddata = json.load(f)
	if 'CVE_Items' not in nvddata.keys():
		logging.error("Wrong format, not exist CVE_Items property")
		return -2
	lstcvejson = nvddata['CVE_Items']
	logging.info("Loaded %d records" % len(lstcvejson))
	# foreach cve record
	# 1. create cve record info: id, original properties
	# 2. get list affect version from orginal configurations properties
	retcount = 0
	for cvejson in lstcvejson:
		try:
			# keep raw data and get up some importance properties to first level properties
			cveid = cvejson['cve']['CVE_data_meta']['ID']
			logging.info("Processing ID %s" % cveid)
			if 'impact' not in cvejson.keys() or 'baseMetricV2' not in cvejson['impact'].keys():
				logging.info("The CVE %s has not any information" % cveid)
				continue
			if checkCveExist(cveid):
				logging.info("CVE %s is existing!" % cveid)
				continue
			if 'baseMetricV3' in cvejson['impact'].keys():
				cvejson['baseScore'] = cvejson['impact']['baseMetricV3']['cvssV3']['baseScore']
				cvejson['vectorString'] = cvejson['impact']['baseMetricV3']['cvssV3']['vectorString']
			else:
				cvejson['baseScore'] = cvejson['impact']['baseMetricV2']['cvssV2']['baseScore']
				cvejson['vectorString'] = cvejson['impact']['baseMetricV2']['cvssV2']['vectorString']
			cvejson['CVEID'] = cveid
			vultype = getVulTypeFromCVE(cvejson)
			cvejson['vultype'] = vultype
			cvejson['history'] = ["Created at %s from %s" % (datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), os.path.basename(JsonfilePath))]
			lstcpe = []
			cvejson['affected'] =  getAllcpeUriFromConf(cvejson['configurations'], lstcpe)
			cveobjid = insertNewCVE(cvejson)
			if cveobjid == -1:
				time.sleep(1)
				# retry
				cveobjid = insertNewCVE(cvejson)
				if cveobjid == -1:
					exit(-1)
			updateVulTypeCollection(cvejson["CVEID"], vultype)

			# 3. push cveid to vendors, product and version collections
			for versionstr in cvejson['affected']:
				# 3.1 push to versions
				addCveidtoVersion(versionstr, cvejson)
				arraf = versionstr.split(':')
				vendorstr = arraf[1]
				productstr = "%s:%s:%s" % (arraf[0], arraf[1], arraf[2])
				# 3.2 push to product
				addCveidtoProduct(productstr, versionstr, cvejson)
				# 3.3 push to vendor
				addCveidtoVendor(vendorstr, productstr, cvejson)
			retcount = retcount + 1
		except Exception as e:
			logging.error("Exception in importCVEFromJsonfile %s" % e)
			traceback.print_exc()
			pass

	logging.info("importCVEFromJsonfile done with file %s" % JsonfilePath)
	return retcount

def updateCVEFromJsonfile(JsonfilePath):
	logging.info("Starting updateCVEFromJsonfile with file %s" % JsonfilePath)
	if not os.path.isfile(JsonfilePath):
		logging.error("File %s is not exist" % JsonfilePath)
		return -1
	# read file to json
	with open(JsonfilePath, encoding="utf8") as f:
		nvddata = json.load(f)
	if 'CVE_Items' not in nvddata.keys():
		logging.error("Wrong format, not exist CVE_Items property")
		return -2
	lstcvejson = nvddata['CVE_Items']
	logging.info("Loaded %d records" % len(lstcvejson))
	# foreach cve record
	# 1. get cve record info: id, original properties
	# 2. get list affect version object id from orginal configurations properties
	retcount = 0
	updatecount = 0
	lastcveupdate = []
	for cvejson in lstcvejson:
		try:
			# keep raw data and get up some importance properties to first level properties
			cveid = cvejson['cve']['CVE_data_meta']['ID']
			logging.info("Processing ID %s" % cveid)
			if 'impact' not in cvejson.keys() or 'baseMetricV2' not in cvejson['impact'].keys():
				logging.info("The CVE %s has not any information" % cveid)
				continue
			if 'baseMetricV3' in cvejson['impact'].keys():
				cvejson['baseScore'] = cvejson['impact']['baseMetricV3']['cvssV3']['baseScore']
				cvejson['vectorString'] = cvejson['impact']['baseMetricV3']['cvssV3']['vectorString']
			else:
				cvejson['baseScore'] = cvejson['impact']['baseMetricV2']['cvssV2']['baseScore']
				cvejson['vectorString'] = cvejson['impact']['baseMetricV2']['cvssV2']['vectorString']
			cvejson['CVEID'] = cveid
			vultype = getVulTypeFromCVE(cvejson)
			cvejson['vultype'] = vultype
			lstcpe = []
			cvejson['affected'] =  getAllcpeUriFromConf(cvejson['configurations'], lstcpe)

			existcve = getCVE(cveid)
			if existcve == 0:
				# add new cve
				logging.info("CVE %s is not exist => add new" % cveid)
				cvejson['history'] = ["Created at %s from %s" % (datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), os.path.basename(JsonfilePath))]
				if len(lastcveupdate) >= 20:
					lastcveupdate.pop(0)
				lastcveupdate.append({"CVEID": cveid, "timeupdate": cvejson['lastModifiedDate']})
				cveobjid = insertNewCVE(cvejson)
				if cveobjid == -1:
					time.sleep(1)
					# retry
					cveobjid = insertNewCVE(cvejson)
					if cveobjid == -1:
						exit(-1)
				updateVulTypeCollection(cvejson["CVEID"], vultype)

				# 3. push cveid to vendors, product and version collections
				for versionstr in cvejson['affected']:
					# 3.1 push to versions
					addCveidtoVersion(versionstr, cvejson)
					arraf = versionstr.split(':')
					vendorstr = arraf[1]
					productstr = "%s:%s:%s" % (arraf[0], arraf[1], arraf[2])
					# 3.2 push to product
					addCveidtoProduct(productstr, versionstr, cvejson)
					# 3.3 push to vendor
					addCveidtoVendor(vendorstr, productstr, cvejson)
				retcount = retcount + 1
			else:
				# check latest
				if existcve['lastModifiedDate'] == cvejson['lastModifiedDate']:
					logging.info("Update CVE %s is not new!" % cveid)
					continue
				# update
				existcve['history'].append("Updated at %s from %s" % (datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), os.path.basename(JsonfilePath)))
				cvejson['history'] = existcve['history']
				if len(lastcveupdate) >= 20:
					lastcveupdate.pop(0)
				lastcveupdate.append({"CVEID": cveid, "timeupdate": cvejson['lastModifiedDate']})
				newversions = []
				newproducts = []
				newvendors = []
				for versionstr in cvejson['affected']:
					newversions.append(versionstr)
					arraf = versionstr.split(':')
					vendorstr = arraf[1]
					productstr = "%s:%s:%s" % (arraf[0], arraf[1], arraf[2])
					newproducts.append(productstr)
					newvendors.append(vendorstr)
				existversions = []
				existproducts = []
				existvendors = []
				for versionstr in existcve['affected']:
					existversions.append(versionstr)
					arraf = versionstr.split(':')
					vendorstr = arraf[1]
					productstr = "%s:%s:%s" % (arraf[0], arraf[1], arraf[2])
					existproducts.append(productstr)
					existvendors.append(vendorstr)
				# 3.2.2. get removed version, removed product and removed vendor => remove
				for oldversion in list(set(existversions) - set(newversions)):
					delCveidfromVersion(oldversion, cvejson)
					logging.debug("Removed version %s for cve %s" % (oldversion, cveid))
				for oldproduct in list(set(existproducts) - set(newproducts)):
					delCveidfromProduct(oldproduct, cvejson)
					logging.debug("Removed product %s for cve %s" % (oldproduct, cveid))
				for oldvendor in list(set(existvendors) - set(newvendors)):
					delCveidfromVendor(oldvendor, cvejson)
					logging.debug("Removed vendor %s for cve %s" % (oldvendor, cveid))
				# 3.2.3. get added version => add
				for newversion in list(set(newversions) - set(existversions)):
					addCveidtoVersion(newversion, cvejson)
					arraf = newversion.split(':')
					vendorstr = arraf[1]
					productstr = "%s:%s:%s" % (arraf[0], arraf[1], arraf[2])
					# 3.2 push to product
					addCveidtoProduct(productstr, newversion, cvejson)
					# 3.3 push to vendor
					addCveidtoVendor(vendorstr, productstr, cvejson)
				replaceCVE(cveid, cvejson)
				updatecount = updatecount + 1
		except Exception as e:
			logging.error("Exception in importCVEFromJsonfile %s" % e)
			pass

	logging.info("updateCVEFromJsonfile done with file %s: %d cve imported and %d cve updated" % (JsonfilePath, retcount, updatecount))
	# save statistics last cve update
	if(len(lastcveupdate) == 20):
		saveStatistic("lastcveupdate", lastcveupdate)
	else:
		existlastcve = getStatistic("lastcveupdate")
		if existlastcve == "0":
			saveStatistic("lastcveupdate", lastcveupdate)
		else:
			lencur = len(lastcveupdate)
			for i in range(lencur-1):
				if len(existlastcve) >= 20:
					existlastcve.pop(0)
				existlastcve.append(lastcveupdate[lencur - i - 1])
		saveStatistic("lastcveupdate", existlastcve)

	countCveSynced = getConfigkey("countcvesynced")
	if countCveSynced == "0":
		saveConfigkey("countcvesynced", retcount)
	else:
		saveConfigkey("countcvesynced", retcount + countCveSynced)
	return retcount

# I. Import offline
def importCVEOffline(cvefolder):
	logging.info("Starting import CVE from file in folder %s" % cvefolder)
	if not os.path.isdir(cvefolder):
		logging.error("Folder %s is not exits" % cvefolder)
		return 0
	cvefiles = [f for f in listdir(cvefolder) if isfile(join(cvefolder, f))]
	importedcvecount = 0
	try:
		lstthread = []
		for cvefile in cvefiles:
			t = threading.Thread(target=importCVEFromJsonfile, args=(join(cvefolder, cvefile),))
			lstthread.append(t)
		for t in lstthread:
		    t.start()
		for t in lstthread:
		    t.join()
		
		fixdoublerecord() # cause multi thread
	except Exception as e:
	   logging.error("Error with exception: %s" % e)
	   exit(0)

	saveConfigkey("createdtime", datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
	saveConfigkey("lastupdated", datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
	logging.info("Import CVE from file in folder %s DONE with %d cves" % (cvefolder, importedcvecount))

def downloadUnzipFile(url, folder):
	try:
		logging.info("Downloading from %s to %s" % (url, folder))
		filename = os.path.basename(urlparse(url).path)
		r = requests.get(url, allow_redirects=True)
		if r.status_code != 200:
			logging.info("The url %s is not found" % url)
			return ""
		with open(folder + filename, 'wb') as f:
			f.write(r.content)
		with ZipFile(folder + filename, 'r') as zip:
			zip.extractall(folder)
		os.remove(folder + filename)
		logging.info("Download done at %s" % folder + os.path.splitext(filename)[0])
		return folder + os.path.splitext(filename)[0]
	except Exception as e:
		logging.error("Exception in downloadFile %s" % e)
		return ""

# II. Import online
def importCVEOnline():
	# clean db
	collist = mongo.db.list_collection_names()
	if "configuration" in collist:
		mongo.db.configuration.delete_many({})
	else:
		newcol = mongo.db["configuration"]
	if "cves" in collist:
		mongo.db.cves.delete_many({})
	else:
		newcol = mongo.db["cves"]
	if "products" in collist:
		mongo.db.products.delete_many({})
	else:
		newcol = mongo.db["products"]
	if "vendors" in collist:
		mongo.db.vendors.delete_many({})
	else:
		newcol = mongo.db["vendors"]
	if "versions" in collist:
		mongo.db.versions.delete_many({})
	else:
		newcol = mongo.db["versions"]
	if "vultypes" in collist:
		mongo.db.vultypes.delete_many({})
	else:
		newcol = mongo.db["vultypes"]
	if "statistics" in collist:
		mongo.db.vultypes.delete_many({})
	else:
		newcol = mongo.db["statistics"]

	cvefolder = "/tmp/cvedownload/"
	if os.path.isdir(cvefolder):
		shutil.rmtree(cvefolder)
	os.mkdir(cvefolder)
	# download cve from nvd
	logging.info("Starting download all cve data from NVD to %s" % cvefolder)
	baseUrl = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-%d.json.zip"
	cveYear = 2002
	while True:
		if downloadUnzipFile(baseUrl % cveYear, cvefolder) == "":
			break
		cveYear = cveYear + 1
	logging.info("Download DONE all cve data from NVD to %s" % cvefolder)
	# import folder to mongo
	importCVEOffline(cvefolder)

def getHashMetaOnline(url):
	logging.info("Starting getHashMetaOnline from %s" % url)
	try:
		res = requests.get(url)
		bodyres = res.text
		arhash = bodyres.split("sha256:")
		if len(arhash) != 2:
			logging.error("The meta data in %s is wrong format!" % url)
			return 0
		logging.info("DONE getHashMetaOnline from %s" % url)
		return arhash[1].strip()
	except Exception as e:
		logging.error("Exception in getHashMetaOnline: %s" % e)
		return 0

# III. Update
def updateCVEOnline():
	logging.info("Starting update CVE Online")
	# 1. check last syntime, if over 8 days, the process will be exit
	lastupdated = getConfigkey("lastupdated")
	if lastupdated == "0":
		logging.error("Please synchronize data from NVD first!")
		return 0
	lastupdateobj = datetime.datetime.strptime(lastupdated, "%Y-%m-%dT%H:%M:%SZ")
	if (datetime.datetime.now() - lastupdateobj).days >= 7:
		logging.error("Data is out of date (over 7days), please recreate date from NVD!")
		return 0
	# 2. check recent added
	cvefolder = "/tmp/updatedownload/"
	if os.path.isdir(cvefolder):
		shutil.rmtree(cvefolder)
	os.mkdir(cvefolder)
	# 2.1. check hash
	nvdhash = getHashMetaOnline("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.meta")
	lastrecenthash = getConfigkey("lastrecenthash")
	# 2.2. import new cve if hash changed
	if nvdhash != lastrecenthash:
		filedownload = downloadUnzipFile("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.zip", cvefolder)
		if filedownload == "":
			logging.error("Cannot download recent file")
			return 0
		importedcvecount = importCVEFromJsonfile(filedownload)
		countCveSynced = getConfigkey("countcvesynced")
		if countCveSynced == "0":
			saveConfigkey("countcvesynced", importedcvecount)
		else:
			saveConfigkey("countcvesynced", importedcvecount + countCveSynced)
		saveConfigkey("lastrecenthash", nvdhash)
	# 3. check cve modified
	# 3.1. check hash
	nvdhash = getHashMetaOnline("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta")
	lastmodifiedhash = getConfigkey("lastmodifiedhash")
	# 3.2. if hash changed, foreach cve
	if nvdhash != lastmodifiedhash:
		filedownload = downloadUnzipFile("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip", cvefolder)
		if filedownload == "":
			logging.error("Cannot download modified file")
			return 0
		importedcvecount = updateCVEFromJsonfile(filedownload)
		countCveSynced = getConfigkey("countcvesynced")
		if countCveSynced == "0":
			saveConfigkey("countcvesynced", importedcvecount)
		else:
			saveConfigkey("countcvesynced", importedcvecount + countCveSynced)
		saveConfigkey("lastmodifiedhash", nvdhash)

	saveConfigkey("lastupdated", datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
	logging.info("DONE update CVE Online")

def syncvultype():
	logging.info("sync vultype Starting...")
	# load vultype
	vultypes = mongo.db.vultypes.find({})
	## sort
	sortedtypes = []
	for vultype in vultypes:
		logging.info("Sorting %s" % vultype["vultype"])
		vultype["cves"].sort()
		new = {}
		new["vultype"] = vultype["vultype"]
		new["cves"] = vultype["cves"]
		sortedtypes.append(new)
	# vendors
	vendors = mongo.db.vendors.find({})
	for vendor in vendors:
		logging.info("Updating vendor %s" % vendor['vendorid'])
		vendorvuls = []
		sortedcve = vendor["cves"].copy() # outofdate struct
		sortedcve.sort()
		for vultype in sortedtypes:
			vulcom = list(set(vultype["cves"]).intersection(sortedcve))
			new = vultype.copy()
			new["cves"] = vulcom
			vendorvuls.append(new)

		statistics = []
		for year in range(1999, datetime.date.today().year+1):
			stat = {}
			stat["year"] = year
			cvestr = "cve-%d" % year
			stat["vuls"] = {}
			for vultype in vendorvuls:
				count = 0
				for cve in vultype["cves"]:
					if cve.lower().startswith(cvestr):
						count = count + 1
				# new = {}
				# new[vultype["vultype"]] = count
				# stat["vuls"].append(new)
				stat["vuls"][vultype["vultype"]] = count
			statistics.append(stat)

		# update to db
		findrecord = {}
		findrecord['vendorid'] = vendor['vendorid']
		newvalues = { "$set": { "vulstat": statistics } }
		#logging.info("Statistics %s" % statistics)
		mongo.db.vendors.update_one(findrecord, newvalues)

	# products
	products = mongo.db.products.find({})
	for product in products:
		logging.info("Updating product %s" % product['productid'])
		productvuls = []
		sortedcve = product["cves"].copy()
		sortedcve.sort()
		for vultype in sortedtypes:
			vulcom = list(set(vultype["cves"]).intersection(sortedcve))
			new = vultype.copy()
			new["cves"] = vulcom
			productvuls.append(new)
		statistics = []
		for year in range(1999, datetime.date.today().year+1):
			stat = {}
			stat["year"] = year
			cvestr = "cve-%d" % year
			stat["vuls"] = {}
			for vultype in productvuls:
				count = 0
				for cve in vultype["cves"]:
					if cve.lower().startswith(cvestr):
						count = count + 1
				# new = {}
				# new[vultype["vultype"]] = count
				#stat["vuls"].append(new)
				stat["vuls"][vultype["vultype"]] = count
			statistics.append(stat)

		# update to db
		findrecord = {}
		findrecord['productid'] = product['productid']
		newvalues = { "$set": { "vulstat": statistics } }
		#logging.info("Statistics %s" % statistics)
		mongo.db.products.update_one(findrecord, newvalues)
	
	saveConfigkey("lastsync", datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
	logging.info("sync vultype Done")

# cause import deadlock via multi thread
def fixdoublerecord():
	# vendor
	dvendors = mongo.db.vendors.aggregate([{"$group" : { "_id": "$vendorid", "count": { "$sum": 1 } } }, {"$match": {"_id" :{ "$ne" : None } , "count" : {"$gt": 1} } }, {"$sort": {"count" : -1} }, {"$project": {"vendorid" : "$_id", "_id" : 0} } ])
	for vid in dvendors:
		logging.info("Double Fixing vendor %s" % vid)
		vendors = list(mongo.db.vendors.find({ "vendorid": vid["vendorid"] }))
		newvendor = {}
		newvendor["vendorid"] = vid["vendorid"]
		cves = []
		products = []
		numberofcve = 0
		scorestat = {}
		avgscore = 0
		vulstat = []
		for vendor in vendors:
			cves = cves + vendor["cves"]
			products = products + vendor["products"]
			for s in vendor["scorestat"].keys():
				if s in scorestat.keys():
					scorestat[s] = scorestat[s] + vendor["scorestat"][s]
				else:
					scorestat[s] = vendor["scorestat"][s]
			avgscore = (avgscore * numberofcve + vendor["numberofcve"] * vendor["avgscore"]) / (numberofcve + vendor["numberofcve"])
			numberofcve = numberofcve + vendor["numberofcve"]
			for stat in vendor["vulstat"]:
				bfound = False
				for idx, cstat in enumerate(vulstat):
					if stat["year"] == cstat["year"]:
						bfound = True
						for vul in cstat["vuls"].keys():
							cstat["vuls"][vul] = cstat["vuls"][vul] + stat["vuls"][vul]
						vulstat[idx] = cstat.copy()
						break
				if not bfound:
					vulstat.append(stat)
			mongo.db.vendors.delete_one({"_id": vendor["_id"]})
		newvendor["cves"] = cves # outofdate struct
		newvendor["products"] = list(set(products)) # unique
		newvendor["scorestat"] = scorestat
		newvendor["numberofcve"] = numberofcve
		newvendor["avgscore"] = avgscore
		newvendor["vulstat"] = vulstat
		mongo.db.vendors.insert_one(newvendor)

	# product
	dproducts = mongo.db.products.aggregate([{"$group" : { "_id": "$productid", "count": { "$sum": 1 } } }, {"$match": {"_id" :{ "$ne" : None } , "count" : {"$gt": 1} } }, {"$sort": {"count" : -1} }, {"$project": {"productid" : "$_id", "_id" : 0} } ])
	for pid in dproducts:
		logging.info("Double Fixing product %s" % pid)
		products = list(mongo.db.products.find({ "productid": pid["productid"] }))
		newproduct = {}
		newproduct["productid"] = pid["productid"]
		cves = []
		versions = []
		numberofcve = 0
		scorestat = {}
		avgscore = 0
		vulstat = []
		for product in products:
			cves = cves + product["cves"]
			versions = versions + product["versions"]
			for s in product["scorestat"].keys():
				if s in scorestat.keys():
					scorestat[s] = scorestat[s] + product["scorestat"][s]
				else:
					scorestat[s] = product["scorestat"][s]
			avgscore = (avgscore * numberofcve + product["numberofcve"] * product["avgscore"]) / (numberofcve + product["numberofcve"])
			numberofcve = numberofcve + product["numberofcve"]
			for stat in product["vulstat"]:
				bfound = False
				for idx, cstat in enumerate(vulstat):
					if stat["year"] == cstat["year"]:
						bfound = True
						for vul in cstat["vuls"].keys():
							cstat["vuls"][vul] = cstat["vuls"][vul] + stat["vuls"][vul]
						vulstat[idx] = cstat.copy()
						break
				if not bfound:
					vulstat.append(stat)
			mongo.db.products.delete_one({"_id": product["_id"]})
		newproduct["cves"] = cves
		newproduct["versions"] = list(set(versions)) # unique
		newproduct["scorestat"] = scorestat
		newproduct["numberofcve"] = numberofcve
		newproduct["avgscore"] = avgscore
		newproduct["vulstat"] = vulstat
		mongo.db.products.insert_one(newproduct)

	# version
	dversions = mongo.db.versions.aggregate([{"$group" : { "_id": "$versionid", "count": { "$sum": 1 } } }, {"$match": {"_id" :{ "$ne" : None } , "count" : {"$gt": 1} } }, {"$sort": {"count" : -1} }, {"$project": {"versionid" : "$_id", "_id" : 0} } ])
	for vid in dversions:
		logging.info("Double Fixing version %s" % vid)
		versions = list(mongo.db.versions.find({ "versionid": vid["versionid"] }))
		newversion = {}
		newversion["versionid"] = vid["versionid"]
		cves = []
		numberofcve = 0
		scorestat = {}
		avgscore = 0
		vulstat = []
		for version in versions:
			cves = cves + version["cves"]
			for s in version["scorestat"].keys():
				if s in scorestat.keys():
					scorestat[s] = scorestat[s] + version["scorestat"][s]
				else:
					scorestat[s] = version["scorestat"][s]
			avgscore = (avgscore * numberofcve + version["numberofcve"] * version["avgscore"]) / (numberofcve + version["numberofcve"])
			numberofcve = numberofcve + version["numberofcve"]
			for stat in version["vulstat"]:
				bfound = False
				for idx, cstat in enumerate(vulstat):
					if stat["year"] == cstat["year"]:
						bfound = True
						for vul in cstat["vuls"].keys():
							cstat["vuls"][vul] = cstat["vuls"][vul] + stat["vuls"][vul]
						vulstat[idx] = cstat.copy()
						break
				if not bfound:
					vulstat.append(stat)
			mongo.db.versions.delete_one({"_id": version["_id"]})
		newversion["cves"] = cves
		newversion["scorestat"] = scorestat
		newversion["numberofcve"] = numberofcve
		newversion["avgscore"] = avgscore
		newversion["vulstat"] = vulstat
		mongo.db.versions.insert_one(newversion)

def fixnumbercve():
	# vendor
	vendors = mongo.db.vendors.find({})
	index = 0
	for vendor in vendors:
		index = index + 1
		logging.info("Fixing score of vendor %d %s" % (index, vendor["vendorid"]))
		numberofcve = len(vendor["cves"]) # outofdate
		if numberofcve == 0:
			vendor["numberofcve"] = 0
			vendor["avgscore"] = 0
		else:
			sumcvescore = list(mongo.db.cves.aggregate([ { "$match": {"CVEID": { "$in": vendor["cves"]}} }, { "$group":  { "_id" : None, "sum" : { "$sum": "$baseScore" } }}]))
			if len(sumcvescore) == 0:
				avgscore = 0
			else:
				avgscore = sumcvescore[0]["sum"]/numberofcve
		vendor["numberofcve"] = numberofcve
		vendor["avgscore"] = avgscore
		finditem = {}
		finditem["vendorid"] = vendor["vendorid"]
		mongo.db.vendors.replace_one(finditem, vendor)

	# product
	products = mongo.db.products.find({})
	index = 0
	for product in products:
		index = index + 1
		logging.info("Fixing score of product %d %s" % (index, product["productid"]))
		numberofcve = len(product["cves"])
		if numberofcve == 0:
			product["numberofcve"] = 0
			product["avgscore"] = 0
		else:
			sumcvescore = list(mongo.db.cves.aggregate([ { "$match": {"CVEID": { "$in": product["cves"]}} }, { "$group":  { "_id" : None, "sum" : { "$sum": "$baseScore" } }}]))
			if len(sumcvescore) == 0:
				avgscore = 0
			else:
				avgscore = sumcvescore[0]["sum"]/numberofcve
		product["numberofcve"] = numberofcve
		product["avgscore"] = avgscore
		finditem = {}
		finditem["productid"] = product["productid"]
		mongo.db.products.replace_one(finditem, product)

	# version
	versions = mongo.db.versions.find({})
	index = 0
	for version in versions:
		index = index + 1
		logging.info("Fixing score of version %d %s" % (index, version["versionid"]))
		numberofcve = len(version["cves"])
		if numberofcve == 0:
			version["numberofcve"] = 0
			version["avgscore"] = 0
		else:
			sumcvescore = list(mongo.db.cves.aggregate([ { "$match": {"CVEID": { "$in": version["cves"]}} }, { "$group":  { "_id" : None, "sum" : { "$sum": "$baseScore" } }}]))
			if len(sumcvescore) == 0:
				avgscore = 0
			else:
				avgscore = sumcvescore[0]["sum"]/numberofcve
		version["numberofcve"] = numberofcve
		version["avgscore"] = avgscore
		finditem = {}
		finditem["versionid"] = version["versionid"]
		mongo.db.versions.replace_one(finditem, version)
	
def updateStatistics():
	logging.info("updateStatistics Starting...")
	# count cve
	countcve = mongo.db.cves.count()
	# count vendor
	countvendor = mongo.db.vendors.count()
	# count product
	countproduct = mongo.db.products.count()
	# count version
	countversion = mongo.db.versions.count()
	saveStatistic("countstat", {"cve": countcve, "vendor": countvendor, "product": countproduct, "version": countversion})
	# avg score
	avgscore = list(mongo.db.cves.aggregate([{"$group":{"_id":"_id", "avgScore": { "$avg": "$baseScore" }}}]))
	saveStatistic("avgscore", avgscore[0]["avgScore"])

	# top 50 vendor
	topvendor = list(mongo.db.vendors.find().sort("numberofcve",-1).limit(50))
	saveStatistic("topvendor", topvendor)
	# top 50 product
	topproduct = list(mongo.db.products.find().sort("numberofcve",-1).limit(50))
	saveStatistic("topproduct", topproduct)

	# hotest cve
	# in top vendor and in this year and recent update
	# get all cve in top vendor
	topcve = []
	for vendor in topvendor:
		findrec = {}
		findrec["nameid"] = vendor["vendorid"]
		cvelist = mongo.db.cvelists.find_one(findrec)
		if cvelist:
			topcve = topcve + cvelist["cves"]
	yearregex = "^CVE-%d-.*" % datetime.date.today().year
	hotestcve = list(mongo.db.cves.find({"$and": [{"CVEID": {"$in": topcve}}, {"CVEID": {"$regex": yearregex}}]}).sort([("baseScore", -1), ("lastModifiedDate", -1)]).limit(10))
	if len(hotestcve) < 10:
		yearregex = "^CVE-%d-.*" % (datetime.date.today().year - 1)
		hotestcve = list(mongo.db.cves.find({"$and": [{"CVEID": {"$in": topcve}}, {"CVEID": {"$regex": yearregex}}]}).sort([("baseScore", -1), ("lastModifiedDate", -1)]).limit(10))
	saveStatistic("hotestcve", hotestcve)

	saveConfigkey("laststatistic", datetime.datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))
	logging.info("updateStatistics Done")

def fixcvelist():
	logging.info("Fixing ")
	# vendor
	vendors = mongo.db.vendors.find({})
	index = 0
	alen = mongo.db.vendors.count()
	for vendor in vendors:
		index = index + 1
		logging.info("Fixing cvelist of vendor %d/%d %s" % (index, alen, vendor["vendorid"]))
		newlist = {}
		newlist["nameid"] = vendor["vendorid"]
		if "cves" not in vendor.keys():
			logging.info("Pass")
			continue
		newlist["cves"] = vendor["cves"]
		mongo.db.cvelists.insert_one(newlist)
		vendor.pop("cves")
		finditem = {}
		finditem["vendorid"] = vendor["vendorid"]
		mongo.db.vendors.replace_one(finditem, vendor)

	# product
	products = mongo.db.products.find({})
	index = 0
	alen = mongo.db.products.count()
	for product in products:
		index = index + 1
		logging.info("Fixing cvelist of product %d/%d %s" % (index, alen, product["productid"]))
		newlist = {}
		newlist["nameid"] = product["productid"]
		if "cves" not in product.keys():
			logging.info("Pass")
			continue
		newlist["cves"] = product["cves"]
		mongo.db.cvelists.insert_one(newlist)
		product.pop("cves")
		finditem = {}
		finditem["productid"] = product["productid"]
		mongo.db.products.replace_one(finditem, product)

	# version
	versions = mongo.db.versions.find({})
	index = 0
	alen = mongo.db.versions.count()
	for version in versions:
		index = index + 1
		logging.info("Fixing cvelist of version %d/%d %s" % (index, alen, version["versionid"]))
		newlist = {}
		newlist["nameid"] = version["versionid"]
		if "cves" not in version.keys():
			logging.info("Pass")
			continue
		newlist["cves"] = version["cves"]
		mongo.db.cvelists.insert_one(newlist)
		version.pop("cves")
		finditem = {}
		finditem["versionid"] = version["versionid"]
		mongo.db.versions.replace_one(finditem, version)

def printUsage():
	print("Usage %s <action> [option]" % sys.argv[0])
	print("List actions:")
	print("+ importonline: Import CVE from NVD")
	print("+ importoffline: Import CVE from a flolder")
	print("+ update: Update CVE From NVD")
	print("+ updatestat: Update Statistics")

#fixcvelist()

if __name__ == "__main__":
	if len(sys.argv) < 2:
		printUsage()
		exit(0)

	if sys.argv[1] == "importonline":
		importCVEOnline()
	elif sys.argv[1] == "importoffline":
		if len(sys.argv) != 3:
			printUsage()
			exit(0)
		importCVEOffline(sys.argv[2])
	elif sys.argv[1] == "update":
		updateCVEOnline()
	elif sys.argv[1] == "updatestat":
		updateStatistics()
	else:
		printUsage()
		exit(0)