#!/usr/bin/python
#
#
#########################################################################################
#                                     Disclaimer                                        #
#########################################################################################
# (c) 2014, Mobile-Sandbox
# Michael Spreitzenbarth (research@spreitzenbarth.de)
#
# This program is free software you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
#########################################################################################
#                          Imports  & Global Variables                                  #
#########################################################################################
# python system imports
import csv
import datetime
import hashlib
import os
import re
import shutil
import subprocess
import ujson as json
import uuid
import glob
import time
from multiprocessing import Pool
import multiprocessing
import threading



import ssdeep

import settings



# global variables
CC = ''.join(map(chr, list(range(0, 32)) + list(range(127, 160))))
sha = None

primary_path = settings.APICALLS
fallback_path = "/home/ubuntu/Simon/andromatch/detectors/Drebin/preprocessing/drebin-authors/APIcalls.txt"
try:
    with open(primary_path) as f:
        apiCallList = f.readlines()
except FileNotFoundError:
    print(f"File not found at {primary_path}. Trying fallback path...")
    if os.path.exists(fallback_path):
        with open(fallback_path) as f:
            apiCallList = f.readlines()
    else:
        raise FileNotFoundError(f"File not found at both {primary_path} and {fallback_path}")

apiCallList = tuple(apiCallList)


#########################################################################################
#                                    Functions                                          #
#########################################################################################
def chunkify(lst, n):
            return [lst[i::n] for i in range(n)]

def checkAPI_process_files(process_name, file_chunk):
    # Log the start time of the function
    thread_start_time = time.time()
    chunk_permissions = set()
    chunk_calls = []
    large_for_loop_start_time = time.time()
    cumul_loop_time = 0
    iteration_times = []

    # Debugging
    debug_directory = "/home/ubuntu/Simon/andromatch/garbage/debugDrebin"
    os.makedirs(debug_directory, exist_ok=True)  # Create the directory if it doesn't exist
    
    
    for num_file, file in enumerate(file_chunk):
        inside_for_loop_start_time = time.time()
        try:
            file_compile_start_time = time.time()
            file = re.compile('[%s]' % re.escape(CC)).sub('', file)
            # print(f"Compile took {time.time() - file_compile_start_time:.2f} seconds")
            with open(file, 'r') as smaliFile:
                for_loop_start_time = time.time()
                read_loop_start_time = time.time()
                smaliContent = smaliFile.read()

                # TODO
                # if "READ_CONTACT" in smaliContent:
                #     debug_file_path = os.path.join(directory, f"{thread_name}_file_{num_file}.txt")

                #     # Write the iteration_times to the file
                #     with open(debug_file_path, 'w') as file:
                #         for time_value in iteration_times:
                #             file.write(f"{time_value}\n")
                    
                #     print(f"Debug info saved to {debug_file_path}")

                # print(f"Read took {time.time() - read_loop_start_time:.2f} seconds")
                for_loop_start_time = time.time()
                for apiCall in apiCallList:
                    apiCallParts = apiCall.split("|")
                    if smaliContent.find(apiCallParts[0]) != -1:
                        try:
                            permission = apiCallParts[1].split("\n")[0]
                        except:
                            permission = ""
                        if permission != "":
                            chunk_permissions.add(permission)
                        # Duplicate checking (permission not in apiPermissions) is done 
                        # during aggregation
                        chunk_calls.append(apiCallParts)
                    # print(f"For loop took {time.time() - inside_for_loop_start_time:.2f} seconds")
                    else:
                        continue
        except Exception as e:
            # Logging the error can be added here if needed
            print("133", e)
            pass
        inside_for_loop_took = time.time() - inside_for_loop_start_time
        iteration_times.append(inside_for_loop_took)
        cumul_loop_time += inside_for_loop_took

    # print(f"Large for loop took {time.time() - large_for_loop_start_time:.2f} seconds")
    # print(f"As stated by {cumul_loop_time:.2f} seconds")
    # print(f"Longest iteration {max(iteration_times):.2f} seconds")

    # ------------------------------------------------------------------------------
    # Uncomment this to save thread datetimes:
    # ----------vvv-----------------------------------------------------------------
    ## Get the name of the current thread
    # thread_name = process_name
    
    ## Log the end time of the function
    # thread_end_time = time.time()

    # print(f"Thread took {thread_end_time - thread_start_time:.2f} seconds")
    # file_path = os.path.join(directory, f"datetime_{thread_name}.txt")

    # # Write the iteration_times to the file
    # with open(file_path, 'w') as file:
    #     file.write(f"started at {thread_start_time:.6f} and ended at {thread_end_time:.6f}\n")
    
    # print(f"Datetimes of the thread saved to {file_path}")
    # ------------------------------------------------------------------------------

    return chunk_permissions, chunk_calls

# get permissions by used API
def checkAPIpermissions(smaliLocation):

    apiPermissions = set()
    apiCalls = []
    # create file-list of directory
    fileList = []
    for dirname, dirnames, filenames in os.walk(smaliLocation):
        for filename in filenames:
            fileList.append(os.path.join(dirname, filename))

    # parse every file in file-list and search for every API call in API-Call-List
    fileList = sorted(fileList)

    if settings.N_CORES <= 1:
        for file in fileList:
            try:
                file = re.compile('[%s]' % re.escape(CC)).sub('', file)
                smaliFile = open(file).read()
                for apiCall in apiCallList:
                    apiCall = apiCall.split("|")
                    if smaliFile.find(apiCall[0]) != -1:
                        try:
                            permission = apiCall[1].split("\n")[0]
                        except:
                            permission = ""
                        if (permission not in apiPermissions) and (
                                permission != ""):
                            apiPermissions.add(permission)
                            #apiCalls.append(apiCall)
                        apiCalls.append(apiCall)
                    else:
                        continue
            except Exception as e:
                # print "File " + file + " has illegal characters in its name!"
                continue

    #region [ rgba(190, 5, 30, 0.3) ] MULTI-THREAD checkAPIpermission
    elif settings.N_CORES > 1:
        def multithread_main(max_workers=None):
            file_chunks = chunkify(fileList, max_workers)
            try:
                with Pool(processes=max_workers) as pool:
                    multithread_start_time = time.time()
                    results = pool.starmap(checkAPI_process_files,
                     [(f"Thread-{i}", chunk) for i, chunk in enumerate(file_chunks)])
                
                    for i, (permissions, calls) in enumerate(results):
                        apiPermissions.update(permissions)
                        apiCalls.extend(calls)
            except Exception as e:
                print("214:", e)

        multithread_main(max_workers=settings.N_CORES)

        # Convert apiPermissions back to a list if needed
        apiPermissions = list(apiPermissions)
    #endregion

    return (apiPermissions, apiCalls)


def named_process_files(name, file_chunk):
    process = multiprocessing.current_process()
    process.name = name
    return process_files(file_chunk)


# create Log file
def createLogFile(logDir):
    if not os.path.exists(logDir):
        os.mkdir(logDir)
    logFile = open(logDir + "static.log", "a+")
    logFile.write("\n\n\n")
    logFile.write(
        "              ___.   .__.__                                                .______.                                                  \n")
    logFile.write(
        "  _____   ____\_ |__ |__|  |   ____               ___________    ____    __| _/\_ |__   _______  ___       ____  ____   _____        \n")
    logFile.write(
        " /     \ /  _ \| __ \|  |  | _/ __ \    ______   /  ___/\__  \  /    \  / __ |  | __ \ /  _ \  \/  /     _/ ___\/  _ \ /     \       \n")
    logFile.write(
        "|  Y Y  (  <_> ) \_\ \  |  |_\  ___/   /_____/   \___ \  / __ \|   |  \/ /_/ |  | \_\ (  <_> >    <      \  \__(  <_> )  Y Y  \      \n")
    logFile.write(
        "|__|_|  /\____/|___  /__|____/\___  >           /____  >(____  /___|  /\____ |  |___  /\____/__/\_ \  /\  \___  >____/|__|_|  /      \n")
    logFile.write(
        "      \/           \/             \/                 \/      \/     \/      \/      \/            \/  \/      \/            \/       \n")
    logFile.write("\n")
    logFile.write(
        "---------------------------------------------------------------------------------------------------------------------------------\n")
    logFile.write("\n\t" + "static analysis")
    logFile.write(
        "\n\t" + str(datetime.datetime.today()).split(' ')[0] + "\t-\t" +
        str(datetime.datetime.today()).split(' ')[1].split('.')[0])
    logFile.write("\n\n")
    return logFile


# make local log entries
def log(logFile, file, message, type):
    if type == 0:
        logFile.write("\n")
        logFile.write(
            "-----------------------------------------------------------------------\n")
        logFile.write("\t" + message + "\n")
        logFile.write(
            "-----------------------------------------------------------------------\n")
    if type == 1:
        logFile.write("\t\t" + file + "\t" + message + "\n")


# log file footer
def closeLogFile(logFile):
    logFile.write("\n\n\n")
    logFile.write(
        "---------------------------------------------------------------------------------------------------------------------------------\n")
    logFile.write("\t (c) by mspreitz 2015 \t\t www.mobile-sandbox.com")
    logFile.close()


# create ssdeep hashes
def hash(fileSystemPosition):
    try:
        ssdeepValue = ssdeep.hash_from_file(fileSystemPosition)
        return ssdeepValue
    except Exception as e:
        # print str(e.message)
        ssdeepValue = "(None)"
        return ssdeepValue

# Define a function that takes multiple arguments TODO
def slow_multiply(x, y):
    time.sleep(1)  # Simulate a slow function
    return x * y


# copy the icon
def copyIcon(sampleFile, unpackLocation, workingDir):
    icon = "icon.png"
    manifest = subprocess.Popen([settings.AAPT, 'dump', 'badging', sampleFile],
                                stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    manifest = manifest.communicate(0)[0].split("\n")
    for line in manifest:
        if "application:" in line:
            try:
                icon = line.split("icon='")[1].split("'")[0]
            except:
                continue
        else:
            continue
    try:
        inputFile1 = unpackLocation + "/" + icon
        outputFile = workingDir + "icon.png"
        shutil.copy(inputFile1, outputFile)
    except:
        inputFile1 = settings.EMPTYICON
        outputFile = workingDir + "icon.png"
        shutil.copy(inputFile1, outputFile)


# using baksmali
def dex2X(tmpDir, dexFile):
    # baksmali
    smaliLocation = tmpDir + "smali"
    if not os.path.exists(smaliLocation):
        os.mkdir(smaliLocation)

    # Define the paths
    backsmali_path = settings.BACKSMALI
    backsmali_fallback_path = "/home/ubuntu/Simon/andromatch/detectors/Drebin/preprocessing/drebin-authors/baksmali-2.0.3.jar"
    
    # Check if the primary path exists, if not, use the fallback path
    if not os.path.exists(backsmali_path):
        print(f"Primary path {backsmali_path} does not exist. Using fallback path.")
        backsmali_path = backsmali_fallback_path
    
    print(f"Using backsmali path: {backsmali_path}")
    baksmali = subprocess.Popen(
        ['java', '-Xmx256M', '-jar', backsmali_path, '-o', smaliLocation, dexFile])
    baksmali.wait()
    return smaliLocation


# get all used activities
# the first activity in the list is the MAIN activity
def getActivities(sampleFile):
    activities = []
    #print "into activities"
    manifest = subprocess.Popen([settings.AAPT, 'dump', 'badging', sampleFile],
                                stdout=subprocess.PIPE,
                                stdin=subprocess.PIPE,
                                stderr=subprocess.PIPE)
    manifest = manifest.communicate(0)[0]

    # Decode the byte string to a regular string
    decoded_str = manifest.decode('utf-8')
    
    # Split the string by newline characters
    split_lines = decoded_str.split('\n')

    manifest = split_lines

    for line in manifest:
        if "activity" in line:
            try:
                activity = line.split("'")[1].split(".")[-1]
                activity = re.compile('[%s]' % re.escape(CC)).sub('', activity)
                activity = "." + activity
		      #print activity
                activities.append(activity.encode('ascii', 'replace'))
            except:
                continue
        else:
            continue
    #print activities
    #print 'Part 2'
    manifest = subprocess.Popen(
        [settings.AAPT, 'd', 'xmltree', sampleFile, 'AndroidManifest.xml'],
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE)
    manifest = manifest.communicate(0)[0]

    # Decode the byte string to a regular string
    decoded_str = manifest.decode('utf-8')
    
    # Split the string by newline characters
    split_lines = decoded_str.split('\n')

    manifest = split_lines
    for i, line in enumerate(manifest):
        if "activity" in line:
            try:
                if 'Raw' not in manifest[i+1]:
                    nextLine = manifest[i + 2].split("=")[1].split('"')[1]
                else:
                    nextLine = manifest[i + 1].split("=")[1].split('"')[1]
                #print 'VEDIAMO', nextLine
                nextLine = re.compile('[%s]' % re.escape(CC)).sub('', nextLine)
                if (nextLine not in activities) and (nextLine != ""):
                    activities.append(nextLine.encode('ascii', 'replace'))
                else:
                    continue
            except:
                continue
        else:
            continue
    #print activities
    return activities


# get the used features
def getFeatures(logFile, sampleFile):
    appFeatures = []
    sampleInfos = subprocess.Popen([settings.AAPT, 'd', 'badging', sampleFile],
                                   stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
    sampleInfos = sampleInfos.communicate(0)[0]
    # Decode the byte string to a regular string
    decoded_str = sampleInfos.decode('utf-8')
    
    # Split the string by newline characters
    split_lines = decoded_str.split('\n')
    sampleInfos = split_lines

    log(logFile, 0, "application features", 0)
    for sampleInfo in sampleInfos:
        if sampleInfo.startswith("uses-feature"):
            sampleFeature = sampleInfo.split("'")[1]
            sampleFeature = re.compile('[%s]' % re.escape(CC)).sub('',
                                                                   sampleFeature)
            log(logFile, "Feature:", sampleFeature, 1)
            if (sampleFeature not in appFeatures) and (sampleFeature != ""):
                appFeatures.append(sampleFeature.encode('ascii', 'replace'))
        else:
            continue
    return appFeatures


# get a list of files inside the apk
def getFilesInsideApk(sampleFile):
    appFiles = []
    xml = subprocess.Popen([settings.AAPT, 'list', sampleFile],
                           stdout=subprocess.PIPE,
                           stdin=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    xml = xml.communicate(0)[0]
    decoded_str = xml.decode('utf-8')
    split_lines = decoded_str.split('\n')
    xml = split_lines


    for line in xml:
        try:
            files = line.split("\n")[0]
            files = re.compile('[%s]' % re.escape(CC)).sub('', files)
            if files != "":
                appFiles.append(files.encode('ascii', 'replace'))
        except:
            continue
    return appFiles


# get intents
def getIntents(logFile, sampleFile):
    log(logFile, 0, "used intents", 0)
    appIntents = []
    xml = subprocess.Popen(
        [settings.AAPT, 'd', 'xmltree', sampleFile, 'AndroidManifest.xml'],
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE)
    xml = xml.communicate(0)[0]
    # Decode the byte string to a regular string
    decoded_str = xml.decode('utf-8')
    
    # Split the string by newline characters
    split_lines = decoded_str.split('\n')

    xml = split_lines

    i = 0
    for line in xml:
        if "intent" in line:
            try:
                intents = line.split("=")[1].split("\"")[1]
                intents = re.compile('[%s]' % re.escape(CC)).sub('', intents)
                log(logFile, "AndroidManifest", intents, 1)
                appIntents.append(intents.encode('ascii', 'replace'))
            except:
                continue
        else:
            continue
    return appIntents


# get network
def getNet(sampleFile):
    # print sampleFile
    appNet = []

    xml = subprocess.Popen(
        [settings.AAPT, 'd', 'xmltree', sampleFile, 'AndroidManifest.xml'],
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE)
    xml = xml.communicate(0)[0]

    # Decode the byte string to a regular string
    decoded_str = xml.decode('utf-8')
    
    # Split the string by newline characters
    split_lines = decoded_str.split('\n')

    xml = split_lines

    i = 0
    for line in xml:
        if "android.net" in line:
            try:
                net = line.split("=")[1].split("\"")[1]
                net = re.compile('[%s]' % re.escape(CC)).sub('', net)
                if net != "":
                    appNet.append(net.encode('ascii', 'replace'))
            except:
                continue
        else:
            continue
    return appNet


# get the permissions from the manifest
# different from the permissions when using aapt d xmltree sampleFile AndroidManifest.xml ???
def getPermissions(logFile, sampleFile):
    appPermissions = []
    permissions = subprocess.Popen(
        [settings.AAPT, 'd', 'permissions', sampleFile],
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE)
    #print 'into permissions'
    #print permissions.communicate(0)
    permissions = permissions.communicate(0)[0]

    # Decode the byte string to a regular string
    decoded_str = permissions.decode('utf-8')
    
    # Split the string by newline characters
    split_lines = decoded_str.split('uses-permission: ')

    permissions = split_lines

    log(logFile, 0, "granted permissions", 0)
    i = 1
    while i < len(permissions):
        permission = permissions[i].split("\n")[0]
        permission = re.compile('[%s]' % re.escape(CC)).sub('', permission)
        log(logFile, "Permission:", permission, 1)
        i += 1
        if permission != "":
            appPermissions.append(permission)
    #print appPermissions
    return appPermissions


# get providers
def getProviders(logFile, sampleFile):
    log(logFile, 0, "used providers", 0)
    appProviders = []
    xml = subprocess.Popen(
        [settings.AAPT, 'd', 'xmltree', sampleFile, 'AndroidManifest.xml'],
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE)
    xml = xml.communicate(0)[0]

    # Decode the byte string to a regular string
    decoded_str = xml.decode('utf-8')
    
    # Split the string by newline characters
    split_lines = decoded_str.split('\n')

    xml = split_lines
    for line in xml:
        if "provider" in line:
            try:
                provider = line.split("=")[1].split("\"")[1]
                provider = re.compile('[%s]' % re.escape(CC)).sub('', provider)
                log(logFile, "AndroidManifest", provider, 1)
                if appProviders != "":
                    appProviders.append(provider.encode('ascii', 'replace'))
            except:
                continue
        else:
            continue
    return appProviders


# get some basic information
def getSampleInfo(logFile, sampleFile):
    global sha
    fp = open(sampleFile, 'rb')
    content = fp.read()
    md5OfNewJob = hashlib.md5(content).hexdigest().upper()
    shaOfNewJob = hashlib.sha256(content).hexdigest().upper()
    sha = shaOfNewJob
    fp.close()
    appInfos = []
    log(logFile, 0, "application infos", 0)
    log(logFile, "sha256:", shaOfNewJob, 1)
    appInfos.append(shaOfNewJob)
    log(logFile, "md5:", md5OfNewJob, 1)
    appInfos.append(md5OfNewJob)
    sampleInfos = subprocess.Popen([settings.AAPT, 'd', 'badging', sampleFile],
                                   stdout=subprocess.PIPE,
                                   stdin=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
    sampleInfos = sampleInfos.communicate(0)[0]

    # Decode the byte string to a regular string
    decoded_str = sampleInfos.decode('utf-8')
    
    # Split the string by newline characters
    split_lines = decoded_str.split('\n')
    
    sampleInfos = split_lines

    i = 0
    while i < len(sampleInfos):
        sampleInfo = sampleInfos[i]
        if sampleInfo.startswith("package: name="):
            sampleLable = sampleInfo.split("name=")[1].split("'")[1]
            appInfos.append(sampleLable.encode('ascii', 'replace'))
            log(logFile, "Label:", sampleLable, 1)
            break
        else:
            if i == (len(sampleInfos) - 1):
                sampleLable = "NO_LABEL"
                log(logFile, "Label:", "no application label specified", 1)
                appInfos.append(sampleLable.encode('ascii', 'replace'))
                break
            else:
                i = i + 1
    i = 0
    while i < len(sampleInfos):
        sampleInfo = sampleInfos[i]
        if sampleInfo.startswith("sdkVersion"):
            sampleSdkVersion = sampleInfo.split("'")[1]
            log(logFile, "SDK version:", sampleSdkVersion, 1)
            appInfos.append(sampleSdkVersion)
            break
        else:
            if i == (len(sampleInfos) - 1):
                sampleSdkVersion = "0"
                log(logFile, "SDK version:", "none specified", 1)
                appInfos.append(sampleSdkVersion)
                break
            else:
                i = i + 1
    apkName = str(sampleFile).split("/")[-1]
    appInfos.append(apkName.encode('ascii', 'replace'))
    return appInfos


# get services and receiver
def getServicesReceivers(logFile, sampleFile):
    log(logFile, 0, "used services and receivers", 0)
    servicesANDreceiver = []
    manifest = subprocess.Popen(
        [settings.AAPT, 'd', 'xmltree', sampleFile, 'AndroidManifest.xml'],
        stdout=subprocess.PIPE,
        stdin=subprocess.PIPE,
        stderr=subprocess.PIPE)
    manifest = manifest.communicate(0)[0]
    decoded_str = manifest.decode('utf-8')
    split_lines = decoded_str.split('\n')
    manifest = split_lines
    for i, line in enumerate(manifest):
        if "service" in line:
            try:
                nextLine = manifest[i + 1].split("=")[1].split('"')[1]
                nextLine = re.compile('[%s]' % re.escape(CC)).sub('', nextLine)
                log(logFile, "AndroidManifest", nextLine, 1)
                if (nextLine not in servicesANDreceiver) and (nextLine != ""):
                    servicesANDreceiver.append(
                        nextLine.encode('ascii', 'replace'))
            except:
                continue
        else:
            continue
    for i, line in enumerate(manifest):
        if "receiver" in line:
            try:
                nextLine = manifest[i + 1].split("=")[1].split('"')[1]
                nextLine = re.compile('[%s]' % re.escape(CC)).sub('', nextLine)
                log(logFile, "AndroidManifest", nextLine, 1)
                if (nextLine not in servicesANDreceiver) and (nextLine != ""):
                    servicesANDreceiver.append(
                        nextLine.encode('ascii', 'replace'))
            except:
                continue
        else:
            continue
    return servicesANDreceiver


# helper for parseSmaliCalls
def parseSmaliLine(line, counter, dangerousCalls, smaliFile):
    i = counter
    if "Cipher" in line:
        try:
            prevLine = \
                smaliFile[smaliFile.index(line) - 2].split("\n")[
                    0].split('"')[1]
            if "Cipher(" + prevLine + ")" in dangerousCalls:
                pass
            else:
                dangerousCalls.append("Cipher(" + prevLine + ")")
        except Exception as e:
            # print("735", e)
            pass
    # only for logging !
    if "crypto" in line:
        try:
            line = line.split("\n")[0]
        except Exception as e:
            print("741", e)
    if "Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;)" in line:
         
        if "HTTP GET/POST (Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;))" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "HTTP GET/POST (Ljava/net/HttpURLconnection;->setRequestMethod(Ljava/lang/String;))")
    if "Ljava/net/HttpURLconnection" in line:
         
        if "HttpURLconnection (Ljava/net/HttpURLconnection)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "HttpURLconnection (Ljava/net/HttpURLconnection)")
    if "getExternalStorageDirectory" in line:
         
        if "Read/Write External Storage" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("Read/Write External Storage")
    if "getSimCountryIso" in line:
         
        if "getSimCountryIso" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("getSimCountryIso")
    if "execHttpRequest" in line:
         
        if "execHttpRequest" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("execHttpRequest")
    if "Lorg/apache/http/client/methods/HttpPost" in line:
         
        if "HttpPost (Lorg/apache/http/client/methods/HttpPost)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "HttpPost (Lorg/apache/http/client/methods/HttpPost)")
    if "Landroid/telephony/SmsMessage;->getMessageBody" in line:
         
        if "readSMS (Landroid/telephony/SmsMessage;->getMessageBody)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "readSMS (Landroid/telephony/SmsMessage;->getMessageBody)")
    if "sendTextMessage" in line:
         
        if "sendSMS" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("sendSMS")
    if "getSubscriberId" in line:
         
        if "getSubscriberId" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("getSubscriberId")
    if "getDeviceId" in line:
         
        if "getDeviceId" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("getDeviceId")
    if "getPackageInfo" in line:
         
        if "getPackageInfo" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("getPackageInfo")
    if "getSystemService" in line:
         
        if "getSystemService" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("getSystemService")
    if "getWifiState" in line:
         
        if "getWifiState" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("getWifiState")
    if "system/bin/su" in line:
         
        if "system/bin/su" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("system/bin/su")
    if "setWifiEnabled" in line:
         
        if "setWifiEnabled" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("setWifiEnabled")
    if "setWifiDisabled" in line:
         
        if "setWifiDisabled" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("setWifiDisabled")
    if "getCellLocation" in line:
         
        if "getCellLocation" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("getCellLocation")
    if "getNetworkCountryIso" in line:
         
        if "getNetworkCountryIso" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("getNetworkCountryIso")
    if "SystemClock.uptimeMillis" in line:
         
        if "SystemClock.uptimeMillis" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("SystemClock.uptimeMillis")
    if "getCellSignalStrength" in line:
         
        if "getCellSignalStrength" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("getCellSignalStrength")
    if "Landroid/os/Build;->BRAND:Ljava/lang/String" in line:
         
        if "Access Device Info (Landroid/os/Build;->BRAND:Ljava/lang/String)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Access Device Info (Landroid/os/Build;->BRAND:Ljava/lang/String)")
    if "Landroid/os/Build;->DEVICE:Ljava/lang/String" in line:
         
        if "Access Device Info (Landroid/os/Build;->DEVICE:Ljava/lang/String)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Access Device Info (Landroid/os/Build;->DEVICE:Ljava/lang/String)")
    if "Landroid/os/Build;->MODEL:Ljava/lang/String" in line:
         
        if "Access Device Info (Landroid/os/Build;->MODEL:Ljava/lang/String)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Access Device Info (Landroid/os/Build;->MODEL:Ljava/lang/String)")
    if "Landroid/os/Build;->PRODUCT:Ljava/lang/String" in line:
         
        if "Access Device Info (Landroid/os/Build;->PRODUCT:Ljava/lang/String)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Access Device Info (Landroid/os/Build;->PRODUCT:Ljava/lang/String)")
    if "Landroid/os/Build;->FINGERPRINT:Ljava/lang/String" in line:
         
        if "Access Device Info (Landroid/os/Build;->FINGERPRINT:Ljava/lang/String)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Access Device Info (Landroid/os/Build;->FINGERPRINT:Ljava/lang/String)")
    if "adb_enabled" in line:
         
        if "Check if adb is enabled" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("Check if adb is enabled")
    # used by exploits and bad programers
    if "Ljava/io/IOException;->printStackTrace" in line:
         
        if "printStackTrace" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("printStackTrace")
    if "Ljava/lang/Runtime;->exec" in line:
         
        if "Execution of external commands (Ljava/lang/Runtime;->exec)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Execution of external commands (Ljava/lang/Runtime;->exec)")
    if "Ljava/lang/System;->loadLibrary" in line:
         
        if "Loading of external Libraries (Ljava/lang/System;->loadLibrary)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Loading of external Libraries (Ljava/lang/System;->loadLibrary)")
    if "Ljava/lang/System;->load" in line:
         
        if "Loading of external Libraries (Ljava/lang/System;->load)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Loading of external Libraries (Ljava/lang/System;->load)")
    if "Ldalvik/system/DexClassLoader;" in line:
         
        if "Loading of external Libraries (Ldalvik/system/DexClassLoader;)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Loading of external Libraries (Ldalvik/system/DexClassLoader;)")
    if "Ldalvik/system/SecureClassLoader;" in line:
         
        if "Loading of external Libraries (Ldalvik/system/SecureClassLoader;)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Loading of external Libraries (Ldalvik/system/SecureClassLoader;)")
    if "Ldalvik/system/PathClassLoader;" in line:
         
        if "Loading of external Libraries (Ldalvik/system/PathClassLoader;)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Loading of external Libraries (Ldalvik/system/PathClassLoader;)")
    if "Ldalvik/system/BaseDexClassLoader;" in line:
         
        if "Loading of external Libraries (Ldalvik/system/BaseDexClassLoader;)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Loading of external Libraries (Ldalvik/system/BaseDexClassLoader;)")
    if "Ldalvik/system/URLClassLoader;" in line:
         
        if "Loading of external Libraries (Ldalvik/system/URLClassLoader;)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Loading of external Libraries (Ldalvik/system/URLClassLoader;)")
    if "android/os/Exec" in line:
         
        if "Execution of native code (android/os/Exec)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append(
                "Execution of native code (android/os/Exec)")
    if "Base64" in line:
         
        if "Obfuscation(Base64)" in dangerousCalls:
            pass
        else:
            dangerousCalls.append("Obfuscation(Base64)")
    return dangerousCalls


# executable for parseSmaliCalls
def parseSamliCalls_process_files(process_name, file_chunk):
    dangerousCalls = [] # TODO am I correct to do that?
    for file in file_chunk:
        try:
            file = re.compile('[%s]' % re.escape(CC)).sub('', file)
            smaliFile = open(file).readlines()
            i = 0
            for line in smaliFile:
                i += 1
                dangerousCalls = parseSmaliLine(line, i, dangerousCalls, smaliFile)
        except Exception as e:
            # print "File " + file + " has illegal characters in its name!"
            continue
    return dangerousCalls


# parsing smali-output for suspicious content
def parseSmaliCalls(logFile, smaliLocation):
    log(logFile, 0, "potentially suspicious api-calls", 0)
    dangerousCalls = []
    # create file-list of directory
    fileList = []
    for dirname, dirnames, filenames in os.walk(smaliLocation):
        for filename in filenames:
            fileList.append(os.path.join(dirname, filename))

    if settings.N_CORES <= 1:
        # parse every file in file-list
        for file in fileList:
            try:
                file = re.compile('[%s]' % re.escape(CC)).sub('', file)
                smaliFile = open(file).readlines()
                i = 0
                for line in smaliFile:
                    i += 1
                    dangerousCalls = parseSmaliLine(line, i, dangerousCalls, smaliFile)
            except Exception as e:
                # print "File " + file + " has illegal characters in its name!"
                continue

    #region [ rgba(190, 75, 30, 0.2) ] MULTI-THREAD parseSmaliCalls
    elif settings.N_CORES > 1:
        def multithread_main(max_workers=None):
            dangerousCalls = []
            file_chunks = chunkify(fileList, max_workers)
            try:
                with Pool(processes=max_workers) as pool:
                    multithread_start_time = time.time()
                    results = pool.starmap(parseSamliCalls_process_files,
                    [(f"Thread-{i}", chunk) for i, chunk in enumerate(file_chunks)])
                
                    for i, dangerousCallsResult in enumerate(results):
                        for call in dangerousCallsResult:
                            if call not in dangerousCalls:
                                dangerousCalls.append(call)
            except Exception as e:
                print("Error after threading:", e)
            return dangerousCalls
        
        dangerousCalls = multithread_main(max_workers=settings.N_CORES)
    #endregion
    return dangerousCalls


# helper for parselSmaliURL
def parseSmaliURL_process_files(process_name, file_chunk):
    urls = []
    for file in file_chunk:
        try:
            i = 0
            smaliFile = open(file).readlines()
            for line in smaliFile:
                try:
                    urlPattern = re.search(
                        'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                        line).group()
                    if (urlPattern not in urls) and (urlPattern != ""):
                        urls.append(urlPattern)
                    else:
                        continue
                except:
                    continue
                try:
                    ips = re.search(
                        '(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})',
                        line).group()
                    if (ips not in urls) and (ips != ""):
                        urls.append(ips)
                    else:
                        continue
                except:
                    continue
                i += 1
        except:
            # print "File " + file + " has illegal characters in its name!"
            print("1072 ", e)
            continue
    return urls

# parsing smali-output for URL's and IP's
def parseSmaliURL(logFile, smaliLocation):
    urls = []
    # create file-list of directory
    fileList = []
    log(logFile, 0, "URL's and IP's inside the code", 0)
    for dirname, dirnames, filenames in os.walk(smaliLocation):
        for filename in filenames:
            fileList.append(os.path.join(dirname, filename))

    if settings.N_CORES <= 1:
        # parse every file in file-list
        for file in fileList:
            try:
                i = 0
                smaliFile = open(file).readlines()
                for line in smaliFile:
                    try:
                        urlPattern = re.search(
                            'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
                            line).group()
                        log(logFile, file + ":" + str(i), urlPattern, 1)
                        if (urlPattern not in urls) and (urlPattern != ""):
                            urls.append(urlPattern)
                        else:
                            continue
                    except:
                        continue
                    try:
                        ips = re.search(
                            '(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})',
                            line).group()
                        log(logFile, file + ":" + str(i), ips, 1)
                        if (ips not in urls) and (ips != ""):
                            urls.append(ips)
                        else:
                            continue
                    except:
                        continue
                    i += 1
            except:
                # print "File " + file + " has illegal characters in its name!"
                continue

    #region [ rgba(190, 5, 100, 0.2) ] MULTI-THREAD parseSmaliURL
    elif settings.N_CORES > 1:
        def multithread_main(max_workers=None):
            urls = []
            file_chunks = chunkify(fileList, max_workers)
            try:
                with Pool(processes=max_workers) as pool:
                    multithread_start_time = time.time()
                    results = pool.starmap(parseSmaliURL_process_files,
                    [(f"Thread-{i}", chunk) for i, chunk in enumerate(file_chunks)])
                
                    for i, urlResult in enumerate(results):
                        for url in urlResult:
                            if url not in urls:
                                urls.append(url)
            except Exception as e:
                print("1134:", e)
            return urls

        urls = multithread_main(max_workers=settings.N_CORES)

    #endregion
    return urls


# unpack the sample apk-file
def unpackSample(tmpDir, sampleFile):
    unpackLocation = tmpDir + "unpack"
    if not os.path.exists(unpackLocation):
        os.mkdir(unpackLocation)
    os.system("unzip " + "-o -q -d " + unpackLocation + " " + sampleFile)
    return unpackLocation


# check for Ad-Networks
def detect(smaliLocation):
    with open(settings.ADSLIBS, 'Ur') as f:
        smaliPath = list(tuple(rec) for rec in csv.reader(f, delimiter=';'))
    fileList = list()
    detectedAds = list()
    for dirname, dirnames, filenames in os.walk(smaliLocation):
        for filename in filenames:
            fileList.append(os.path.join(dirname, filename))
    for path in smaliPath:
        adPath = str(path[1])
        for file in fileList:
            if adPath in file:
                if (str(path[0]) not in detectedAds) and (str(path[0]) != ""):
                    detectedAds.append(str(path[0]))
                else:
                    continue
            else:
                continue
    return detectedAds


# create JSON file
def createOutput(workingDir, appNet, appProviders, appPermissions, appFeatures,
                 appIntents, servicesANDreceiver, detectedAds,
                 dangerousCalls, appUrls, appInfos, apiPermissions, apiCalls,
                 appFiles, appActivities, ssdeepValue):
    output = dict()
    output['md5'] = appInfos[1]
    output['sha256'] = appInfos[0]
    output['ssdeep'] = ssdeepValue
    output['package_name'] = appInfos[2]
    output['apk_name'] = appInfos[4]
    output['sdk_version'] = appInfos[3]
    output['app_permissions'] = appPermissions
    output['api_permissions'] = apiPermissions
    output['api_calls'] = apiCalls
    output['features'] = appFeatures
    output['intents'] = appIntents
    output['activities'] = appActivities
    output['s_and_r'] = servicesANDreceiver
    output['interesting_calls'] = dangerousCalls
    output['urls'] = appUrls
    output['networks'] = appNet
    output['providers'] = appProviders
    output['included_files'] = appFiles
    output['detected_ad_networks'] = detectedAds

    # save the JSON dict to a file for later use
    if not os.path.exists(workingDir):
        os.mkdir(workingDir)

    # if not os.path.exists(os.path.join(workingDir, 'results')):
    #     os.mkdir(os.path.join(workingDir, 'results'))

    run_id = '{}drebin-{}@{}'.format(sha, str(uuid.uuid4())[:6],
                                     datetime.datetime.utcnow().strftime(
                                         '%Y-%m-%dT%H:%M:%SZ'))

    output = report_to_feature_vector(output)
    outpath = os.path.join(workingDir, sha + '.json')
    print("saving results at {}...".format(outpath))
    jsonFileName = outpath
    jsonFile = open(jsonFileName, "a+")
    jsonFile.write(json.dumps(output))
    jsonFile.close()
    return output 


def report_to_feature_vector(report):
    output = {'sha256': report['sha256']}

    def key_fmt(k, val):
        return '{}::{}'.format(k, val.strip()).replace('.', '_')

    for k, values in report.items():
        # TODO | Find out what keywords_mapping is
        if k in {'intents', 'features', 'urls', 'api_calls',
                 'interesting_calls', 'app_permissions',
                 'api_permissions', 'activities','s_and_r', 'providers'}:

            if k == 'api_calls':
                for val in values:
                    if val[0].strip() != '':
                        line = key_fmt(k, val[0])
                        output[line] = 1

            elif k == 'interesting_calls':
                for val in values:
                    if 'HttpPost' in val:
                        line = key_fmt(k, val.split(' ')[0])
                        output[line] = 1
                    elif '(' in val and ';' in val:
                        pass
                    elif val.strip() == '':
                        pass
                    elif 'Check if adb is enabled' in val:
                        pass
                    else:
                        line = key_fmt(k, val)
                        output[line] = 1

            else:
                for val in values:
                    if val.strip() != '':
                        line = key_fmt(k, val)
                        output[line] = 1

    return output


#########################################################################################
#                                  MAIN PROGRAMM                                        #
#########################################################################################
def run(sampleFile, workingDir):

    # data = [(1, 2), (3, 4), (5, 6), (7, 8)] # TODO
    
    # fast_start = time.time()
    # with Pool(4) as pool:  # Use 4 processes
    #     results = pool.starmap(slow_multiply, data)
    # print("With Pool.starmap:", results)
    # print("Time taken with Pool.starmap:", time.time() - fast_start)
    
    
    # slow_start = time.time()
    # results = [slow_multiply(x, y) for x, y in data]
    # print("Time taken without Pool.starmap:", time.time() - slow_start)

    total_start_time = time.time()  # Start measuring time
    workingDir = workingDir if workingDir.endswith('/') else workingDir + '/'

    # function calls
    start_time = time.time()
    logFile = createLogFile(workingDir)
    print(f"Log file created in {time.time() - start_time:.2f} seconds")

    start_time = time.time()
    print("unpacking sample...")
    unpackLocation = unpackSample(workingDir, sampleFile)
    print(f"Sample unpacked in {time.time() - start_time:.2f} seconds")

    start_time = time.time()
    print("get Network data...")
    appNet = getNet(sampleFile)
    print(f"Network data obtained in {time.time() - start_time:.2f} seconds")

    start_time = time.time()
    print("get sample info...")
    appInfos = getSampleInfo(logFile, sampleFile)
    print(f"Sample info obtained in {time.time() - start_time:.2f} seconds")

    start_time = time.time()
    print("get providers...")
    appProviders = getProviders(logFile, sampleFile)
    print(f"Providers obtained in {time.time() - start_time:.2f} seconds")

    start_time = time.time()
    print("get permissions...")
    appPermissions = getPermissions(logFile, sampleFile)
    print(f"Permissions obtained in {time.time() - start_time:.2f} seconds")

    start_time = time.time()
    print("get activities...", sampleFile)
    appActivities = getActivities(sampleFile)
    print(f"Activities obtained in {time.time() - start_time:.2f} seconds")

    start_time = time.time()
    print("get features...")
    appFeatures = getFeatures(logFile, sampleFile)
    print(f"Features obtained in {time.time() - start_time:.2f} seconds")

    start_time = time.time()
    print("get intents...")
    appIntents = getIntents(logFile, sampleFile)
    print(f"Intents obtained in {time.time() - start_time:.2f} seconds")

    start_time = time.time()
    print("list files...")
    appFiles = getFilesInsideApk(sampleFile)
    print(f"Files listed in {time.time() - start_time:.2f} seconds")

    start_time = time.time()
    print("get services and receivers...")
    servicesANDreceiver = getServicesReceivers(logFile, sampleFile)
    print(f"Services and receivers obtained in {time.time() - start_time:.2f} seconds")

    start_time = time.time()
    print("create ssdeep hash...")
    ssdeepValue = hash(sampleFile)
    print(f"SSDeep hash created in {time.time() - start_time:.2f} seconds")

    dangerousCalls = []
    appUrls = []
    apiPermissions = []
    apiCalls = []
    detectedAds = []

    dex_files = glob.glob(unpackLocation + '/*.dex')

    for dex in dex_files:
        start_time = time.time()
        print("decompiling sample...")
        smaliLocation = dex2X(workingDir, dex)
        print(f"Sample decompiled in {time.time() - start_time:.2f} seconds")

        start_time = time.time()
        print("search for dangerous calls...")
        dangerousCalls.extend(parseSmaliCalls(logFile, smaliLocation))
        print(f"Dangerous calls searched in {time.time() - start_time:.2f} seconds")

        start_time = time.time()
        print("get URLs and IPs...")
        appUrls.extend(parseSmaliURL(logFile, smaliLocation))
        print(f"URLs and IPs obtained in {time.time() - start_time:.2f} seconds")

        start_time = time.time()
        print("check API permissions...")
        perms, calls = checkAPIpermissions(smaliLocation)
        apiPermissions.extend(perms)
        apiCalls.extend(calls)
        # print("[+] apiPermissions", apiPermissions)
        # print("[+] apiCalls", apiCalls)
        print(f"API permissions checked in {time.time() - start_time:.2f} seconds")

        start_time = time.time()
        print("check for ad networks...")
        detectedAds.extend(detect(smaliLocation))
        print(f"Ad networks checked in {time.time() - start_time:.2f} seconds")

        start_time = time.time()
        print("create json report...")
        shutil.rmtree(smaliLocation)
        print(f"JSON report created in {time.time() - start_time:.2f} seconds")


    createOutput(workingDir, appNet, appProviders, appPermissions, appFeatures,
                 appIntents, servicesANDreceiver, detectedAds,
                 dangerousCalls, appUrls, appInfos, apiPermissions,
                 apiCalls, appFiles, appActivities, ssdeepValue)
    # print("copy icon file...")
    # copyIcon(sampleFile, unpackLocation, workingDir)
    # programm and log footer
    print("close log-file...")
    closeLogFile(logFile)

    end_time = time.time()  # End measuring time
    elapsed_time = end_time - total_start_time
    print(f"Total execution time: {elapsed_time:.2f} seconds")

# if __name__ == "__main__":
#     print("enter main")
#     data = [(1, 2), (3, 4), (5, 6), (7, 8)]
#     # Without Pool.starmap
#     start = time.time()
#     results = [slow_multiply(x, y) for x, y in data]
#     print("Without Pool.starmap:", results)
#     print("Time taken without Pool.starmap:", time.time() - start)

#     # With Pool.starmap
#     start = time.time()
#     with Pool(4) as pool:  # Use 4 processes
#         results = pool.starmap(slow_multiply, data)
#     print("With Pool.starmap:", results)
#     print("Time taken with Pool.starmap:", time.time() - start)
