import csv
import time
import datetime
stop_threads = False
import threading
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
def analyze():
    try:
        index = 0
        extractedData = []
        suspectIP = []
        identifiedIP = []
        global stop_threads
        while not stop_threads:
            data = pandas.read_csv("ResultDirectCapture.csv", encoding= 'unicode_escape', skiprows = index)


        # with open('ResultDirectCapture.csv', newline='') as csvfile:
        #     extractedData = []
        #     suspectIP = []
        #     identifiedIP = []
        #     global stop_threads
        #     while not stop_threads:
        #         row = csvfile.readline().split(',')
        #         row[0:2] = [''.join(row[0:2])]
        #         # print(row)
        #         # break
        #         if not row:
        #             time.sleep(0.5) 
        #         else:
        #             if len(row) > 5 and row[5] == "ftp":
        #                 extractedData.append(row)
        #             for i in extractedData:
        #                 srcIP = i[1]
        #                 srcPort = i[3]

        #                 destIP = i[2]
        #                 destPort = i[4]
                        
        #                 newTime = i[0]

        #                 message = i[len(i)-1].split(' ')
        #                 tempData = findSuspect(srcIP, destIP, suspectIP) 
        #                 detectedData = findSuspect(srcIP, destIP, identifiedIP)  
                            
        #                 # attacker tan cong 
        #                 if destPort == '21' and detectedData is None:
        #                     if tempData is None and message[0] == 'PASS':
        #                         tempRequest = requestIP()
        #                         tempRequest.srcIP = srcIP
        #                         tempRequest.destIP = destIP
        #                         tempRequest.startTime = newTime
        #                         suspectIP.append(tempRequest)
        #                     elif message[0] == 'PASS':
        #                         tempData.attempt += 1
        #                 # server respone
        #                 if tempData is not None and message[0] == '530':
        #                     tempData.fail += 1
        #                 if tempData is not None and tempData.fail > 10  and time_delta(tempData.startTime, newTime) < 2:
        #                     print(f"Detected {srcIP} brute force {destIP} attempted {tempData.attempt} stared in {tempData.startTime}" )
        #                     identifiedIP.append(tempData)
        #                     suspectIP.remove(tempData)
        #                 elif tempData is not None and tempData.fail <= 10 and message[0] == '230':
        #                     identifiedIP.append(tempData)
        #                     suspectIP.remove(tempData)
    except Exception as e:
            print(e)
thread_waitToStop = threading.Thread(target=waitToStop, args=())
thread_run = threading.Thread(target=analyze, args=())
thread_waitToStop.start()
thread_run.start()

thread_waitToStop.join()
thread_run.join()

    # extractedData = []
    # rawData = list(csv.reader(csvfile, delimiter=','))
    # for row in rawData:
    #     if len(row) > 5 and row[5] == "ftp":
    #         extractedData.append(row)
    # extractedData.sort(key=extractedData_sort)
    # 
    # 

            

        




