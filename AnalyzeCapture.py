import csv
import time
import datetime
import threading
import re
from urllib.parse import unquote
import os

stop_threads = False
black_list = ["(?i)(.*)(\\b)+(OR|AND)(\\s)+(true|false)(\\s)*(.*)",
              "(?i)(.*)(\\b)+(OR|AND)(\\s)+(\\w)(\\s)*(\\=)(\\s)*(\\w)(\\s)*(.*)",
              "(?i)(.*)(\\b)+(OR|AND)(\\s)+(equals|not equals)(\\s)+(true|false)(\\s)*(.*)",
              "(?i)(.*)(\\b)+(OR|AND)(\\s)+([0-9A-Za-z_'][0-9A-Za-z\\d_']*)(\\s)*(\\=)(\\s)*([0-9A-Za-z_'][0-9A-Za-z\\d_']*)(\\s)*(.*)",
              "(?i)(.*)(\\b)+(OR|AND)(\\s)+([0-9A-Za-z_'][0-9A-Za-z\\d_']*)(\\s)*(\\!\\=)(\\s)*([0-9A-Za-z_'][0-9A-Za-z\\d_']*)(\\s)*(.*)",
              "(?i)(.*)(\\b)+(OR|AND)(\\s)+([0-9A-Za-z_'][0-9A-Za-z\\d_']*)(\\s)*(\\<\\>)(\\s)*([0-9A-Za-z_'][0-9A-Za-z\\d_']*)(\\s)*(.*)",
              "(?i)(.*)(\\b)+SELECT(\\b)+\\s.*(\\b)(.*)",
              "(?i)(.*)(\\b)+INSERT(\\b)+\\s.*(\\b)+INTO(\\b)+\\s.*(.*)",
              "(?i)(.*)(\\b)+UPDATE(\\b)+\\s.*(.*)",
              "(?i)(.*)(\\b)+DELETE(\\b)+\\s.*(\\b)+FROM(\\b)+\\s.*(.*)",
              "(?i)(.*)(\\b)+UPSERT(\\b)+\\s.*(.*)",
              "(?i)(.*)(\\b)+SAVEPOINT(\\b)+\\s.*(.*)",
              "(?i)(.*)(\\b)+CALL(\\b)+\\s.*(.*)",
              "(?i)(.*)(\\b)+ROLLBACK(\\b)+\\s.*(.*)",
              "(?i)(.*)(\\b)+KILL(\\b)+\\s.*(.*)",
              "(?i)(.*)(\\b)+DROP(\\b)+\\s.*(.*)",
              "(?i)(.*)(\\b)+DESC(\\b)+(\\w)*\\s.*(.*)",
              "(?i)(.*)(\\b)+DESCRIBE(\\b)+(\\w)*\\s.*(.*)",
              "(.*)(/\\*|\\*/|;){1,}(.*)",
              "(.*)(-){2,}(.*)", ]


class color:
    CEND = '\33[0m'
    CRED = '\33[31m'
    CGREEN = '\33[32m'
    CYELLOW = '\33[33m'


class requestIP:
    def __init__(self):
        self.srcIP = ''
        self.destIP = ''
        self.attempt = 1
        self.fail = 0
        self.startTime = ''
        self.succedTime = ''
        self.succedAttempt = 0
        self.exploitTime = ''
        self.uploadedMaliciousFile = False


def extractedData_sort(t):
    return t[0]


def myPrint(t):
    for i in t:
        print(i.srcIP)
        print(i.destIP)
        print(i.attempt)
        print(i.fail)


def findSuspect(srcIP, destIP, suspectList):
    for i in suspectList:
        if (srcIP == i.srcIP and destIP == i.destIP) or (srcIP == i.destIP and destIP == i.srcIP):
            return i
    return None


def waitToStop():
    input()
    global stop_threads
    stop_threads = True


def time_delta(startTime, newTime):
    startTimeSplit = startTime.split(' ')
    newTimeSplit = newTime.split(' ')
    if startTimeSplit[0] == newTimeSplit[0] and startTimeSplit[1] == newTimeSplit[1] and startTimeSplit[2] == newTimeSplit[2] and startTimeSplit[4] == newTimeSplit[4]:
        hourStart = startTimeSplit[3].split(':')
        hourNew = newTimeSplit[3].split(':')
        return (float(hourNew[0]) - float(hourStart[0]))*3600 + (float(hourNew[1]) - float(hourStart[1]))*60 + (float(hourNew[2]) - float(hourStart[2]))
    else:
        return None


def isSqlInjection(data):
    for i in black_list:
        result = re.match(i, data)
        if result != None:
            return True
    return False


def writeLog(data):
    log = open('log.txt', 'a')
    log.write(data)
    log.write('\n')
    log.close()


def deleteLog():
    if os.path.exists("log.txt"):
        os.remove("log.txt")


def analyze():
    deleteLog()
    with open('ResultDirectCapture.csv', newline='', encoding='UTF8') as csvfile:
        suspectIP = []
        identifiedIP = []
        global stop_threads
        while not stop_threads:
            try:
                row = unquote(csvfile.readline()).split(';')
                if not row:
                    time.sleep(0.5)
                elif len(row) > 5:
                    srcIP = row[2]
                    srcPort = row[3]

                    destIP = row[1]
                    destPort = row[4]

                    newTime = row[0].split(' ')
                    newTime = ' '.join(newTime[0:4]).replace(',', '')

                    message = row[len(row)-1].split("\\n")
                    tempData = findSuspect(srcIP, destIP, suspectIP)
                    detectedData = findSuspect(srcIP, destIP, identifiedIP)

                    if row[5].lower() == "http":

                        # attacker tan cong
                        filteredPostForm = [
                            s for s in message if "POST /navigate/login.php HTTP/1.1" in s]
                        if destPort == '80' and detectedData is None and len(filteredPostForm) > 0:
                            filteredMessage = [
                                s for s in message if "Cookie: navigate-user=" in s]
                            if tempData is None and len(filteredMessage) > 0 and isSqlInjection(filteredMessage[0]):
                                tempRequest = requestIP()
                                tempRequest.srcIP = srcIP
                                tempRequest.destIP = destIP
                                tempRequest.startTime = newTime
                                suspectIP.append(tempRequest)
                                resultStr = f"[{newTime}]: Detected {srcIP} attacked {destIP} with SQL Injection, attempted {tempRequest.attempt} stared at {tempRequest.startTime}"
                                writeLog(resultStr)
                                print(color.CYELLOW + resultStr + color.CEND)
                                continue

                            elif len(filteredMessage) > 0 and isSqlInjection(filteredMessage[0]):
                                tempData.attempt += 1
                                resultStr = f"[{newTime}]: Detected {srcIP} attacked {destIP} with SQL Injection, attempted {tempData.attempt}, fail {tempData.fail} time(s) stared at {tempData.startTime}"
                                writeLog(resultStr)
                                print(color.CYELLOW + resultStr + color.CEND)
                                continue

                        elif destPort == '80' and detectedData is not None and len(filteredPostForm) > 0:
                            filteredMessage = [
                                s for s in message if "Cookie: navigate-user=" in s]
                            if len(filteredMessage) > 0 and isSqlInjection(filteredMessage[0]):
                                detectedData.attempt += 1
                                resultStr = f"[{newTime}]: Detected {srcIP} attacked {destIP} with SQL Injection, attempted {detectedData.attempt} time(s), fail {detectedData.fail} time(s), succed {detectedData.succedAttempt} times, stared at {detectedData.startTime} and succed at {detectedData.succedTime}"
                                writeLog(resultStr)
                                print(color.CYELLOW + resultStr + color.CEND)
                                continue

                        # server respone
                        filterResponse = [
                            s for s in message if "HTTP/1.1 302 Found" in s]
                        filterErrorResponse = []
                        filteredFileUpload = []
                        if len([s for s in message if "HTTP/1.1 200 OK" in s]) > 0 and len([s for s in message if "/navigate/navigate_upload.php" in s]) > 0:
                            filteredFileUpload = [
                                "HTTP/1.1 200 OK", "/navigate/navigate_upload.php"]
                        elif len([s for s in message if "HTTP/1.1 200 OK" in s]) > 0 and len([s for s in message if "/navigate/navigate_upload.php" in s]) == 0:
                            filterErrorResponse = ["HTTP/1.1 200 OK"]
                        if tempData is not None and len(filterErrorResponse) > 0:
                            tempData.fail += 1
                            resultStr = f"[{newTime}]: Detected {destIP} failed to attack {srcIP} with SQL Injection, attempted {tempData.attempt} time(s) and fail {tempData.fail} time(s) stared at {tempData.startTime}"
                            writeLog(resultStr)
                            print(color.CGREEN + resultStr + color.CEND)
                            continue

                        elif tempData is not None and len(filterResponse) > 0:
                            resultStr = f"[{newTime}]: Detected {destIP} succed to attack {srcIP} with SQL Injection, attempted {tempData.attempt} stared at {tempData.startTime} succeed login to the system"
                            writeLog(resultStr)
                            print(color.CRED + resultStr + color.CEND)
                            tempData.succedTime = newTime
                            tempData.succedAttempt += 1
                            identifiedIP.append(tempData)
                            suspectIP.remove(tempData)
                            continue

                        elif detectedData is not None and len(filterErrorResponse) > 0:
                            detectedData.fail += 1
                            resultStr = f"[{newTime}]: Detected {destIP} failed to attack {srcIP} with SQL Injection, attempted {detectedData.attempt} time(s), fail {detectedData.fail} time(s), succed {detectedData.succedAttempt} times, stared at {detectedData.startTime} and succed at {detectedData.succedTime}"
                            writeLog(resultStr)
                            print(color.CYELLOW + resultStr + color.CEND)
                            continue

                        elif detectedData is not None and len(filterResponse) > 0:
                            detectedData.succedAttempt += 1
                            resultStr = f"[{newTime}]: Detected {destIP} succed to attack {srcIP} with SQL Injection again, attempted {detectedData.attempt} time(s), fail {detectedData.fail} time(s), succed {detectedData.succedAttempt} times, stared at {detectedData.startTime} and succed at {detectedData.succedTime}"
                            writeLog(resultStr)
                            print(color.CRED + resultStr + color.CEND)
                            continue
                        elif detectedData is not None and detectedData.uploadedMaliciousFile == True and len(filteredFileUpload) > 0:
                            detectedData.exploitTime = newTime
                            resultStr = f"[{newTime}]: Detected {destIP} succed to attack {srcIP} by uploading malicious file, attempted {detectedData.attempt} time(s), fail {detectedData.fail} time(s), succed {detectedData.succedAttempt} times, stared at {detectedData.startTime} and succed at {detectedData.succedTime}"
                            writeLog( resultStr)
                            print(color.CRED + resultStr + color.CEND)
                    elif row[5].lower() == "tcp":
                        if detectedData is not None and detectedData.exploitTime != '':
                            filterExitConnect = [
                                s for s in message if "RST" in s]
                            if detectedData.srcIP == srcIP and len(filterExitConnect) == 0:
                                resultStr = f"[{newTime}]: Detected {srcIP} is exploiting {destIP} stared at {detectedData.exploitTime} "
                                writeLog(resultStr)
                                print(color.CYELLOW + resultStr + color.CEND)
                                continue
                            elif detectedData.destIP == srcIP and len(filterExitConnect) == 0:
                                resultStr = f"[{newTime}]: Detected {srcIP} response to exploit query from {destIP} stared at {detectedData.exploitTime} "
                                writeLog(resultStr)
                                print(color.CYELLOW + resultStr + color.CEND)
                                continue
                            elif len(filterExitConnect) > 0:
                                resultStr = f"[{newTime}]: Detected {srcIP} stop exploiting {destIP} stared at {detectedData.exploitTime} "
                                identifiedIP.remove(detectedData)
                                writeLog(resultStr)
                                print(color.CGREEN + resultStr+ color.CEND) 
                                continue
                    elif row[5].lower() == "media":
                        maliciousFileUpload = [
                            s for s in message if "Type: multipart/form-data" in s]
                        if detectedData is not None and len(maliciousFileUpload) > 0:
                            detectedData.uploadedMaliciousFile = True
                            resultStr = f"[{newTime}]: Detected {srcIP} attacked {destIP} by uploading malicious file, attempted {detectedData.attempt}, fail {detectedData.fail} time(s) stared at {detectedData.startTime}"
                            writeLog(resultStr)
                            print(color.CYELLOW +  resultStr + color.CEND)
                            continue
            except Exception as e:
                print(e)
        csvfile.close()


thread_waitToStop = threading.Thread(target=waitToStop, args=())
thread_run = threading.Thread(target=analyze, args=())
thread_waitToStop.start()
thread_run.start()

thread_waitToStop.join()
thread_run.join()
