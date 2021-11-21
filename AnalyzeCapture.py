import csv
import time
import datetime
import threading
import re

stop_threads = False
black_list = [ "(?i)(.*)(\\b)+(OR|AND)(\\s)+(true|false)(\\s)*(.*)",
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
            "(.*)(-){2,}(.*)",]
class requestIP:
    def __init__(self):
        self.srcIP = ''
        self.destIP = ''
        self.attempt = 1
        self.fail = 0
        self.startTime = ''
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
        return ( float(hourNew[0]) - float(hourStart[0]))*3600 + (float(hourNew[1]) - float(hourStart[1]))*60 + (float(hourNew[2]) - float(hourStart[2]))
    else:
        return None
def isSqlInjection(data):
    for i in black_list:
        result = re.match(i, data)
        if result != None:
            return True
    return False
def analyze():
    try:
        with open('ResultDirectCapture.csv', newline='', encoding='UTF8') as csvfile:
            extractedData = []
            suspectIP = []
            identifiedIP = []
            global stop_threads
            while not stop_threads:
                row = csvfile.readline().split(';')
                if not row:
                    time.sleep(0.5) 
                else:
                    if len(row) > 5 and row[5].lower() == "http":
                        extractedData.append(row)
                    for i in extractedData:
                        srcIP = i[1]
                        srcPort = i[3]

                        destIP = i[2]
                        destPort = i[4]
                        
                        newTime = i[0]

                        message = i[len(i)-1].split("\\n")
                        tempData = findSuspect(srcIP, destIP, suspectIP) 
                        detectedData = findSuspect(srcIP, destIP, identifiedIP)  
                        filteredMessage = [ s for s in message if "Cookie: " in s]
                        # attacker tan cong 
                        if destPort == '80' and detectedData is None:
                            if tempData is None and len(filteredMessage) > 0 and isSqlInjection(filteredMessage[0]):
                                tempRequest = requestIP()
                                tempRequest.srcIP = srcIP
                                tempRequest.destIP = destIP
                                tempRequest.startTime = newTime
                                suspectIP.append(tempRequest)
                            elif len(filteredMessage) > 0 and isSqlInjection(filteredMessage[0]):
                                tempData.attempt += 1
                        # server respone
                        filterResponse = [s for s in message if "HTTP/1.1 200 OK" in s]
                        filterErrorResponse = [s for s in message if "HTTP/1.1 302 Found"]
                        if tempData is not None and len(filterErrorResponse) > 0:
                            tempData.fail += 1
                        elif tempData is not None and len(filterResponse) > 0:
                            print(f"Detected {srcIP} attacked {destIP} with SQL Injection, attempted {tempData.attempt} stared in {tempData.startTime}" )
                            identifiedIP.append(tempData)
                            suspectIP.remove(tempData)
                        # elif tempData is not None and tempData.fail <= 10 and message[0] == '230':
                        #     identifiedIP.append(tempData)
                        #     suspectIP.remove(tempData)
    except Exception as e:
            print(e)
    finally:
        csvfile.close()
# thread_waitToStop = threading.Thread(target=waitToStop, args=())
# thread_run = threading.Thread(target=analyze, args=())
# thread_waitToStop.start()
# thread_run.start()

# thread_waitToStop.join()
# thread_run.join()
analyze()
    # extractedData = []
    # rawData = list(csv.reader(csvfile, delimiter=','))
    # for row in rawData:
    #     if len(row) > 5 and row[5] == "ftp":
    #         extractedData.append(row)
    # extractedData.sort(key=extractedData_sort)
    # 
    # 

            

        




