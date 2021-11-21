import pyshark
import csv
import threading
import time
from os.path import exists

def capture():
    try:
        cap = pyshark.LiveCapture(interface='Ethernet')    
        while True:
            for packet in cap.sniff_continuously(packet_count=5):
                writePacket(packet)
            global stop_threads
            if stop_threads:
                break
        cap.close()
    except Exception as e:
        print(e)
    finally:
        cap.close()
def waitToStop():
    input()
    global stop_threads
    stop_threads = True
def writePacket(packet):
    if not exists('ResultDirectCapture.csv'):
        with open('ResultDirectCapture.csv', 'w') as csvfile:
            CsvWriter = csv.writer(csvfile)
            CsvWriter.writerow(["Time","IP SOURCE", "IP DESTINATION", "SOURCE PORT", "DESTINATION PORT", "PROTOCAL", "LENGTH"])
    with open('ResultDirectCapture.csv', 'a') as csvfile:
        CsvWriter = csv.writer(csvfile)
        row = []
        row.append(str(packet.frame_info.time))
        if hasattr(packet, 'ip'):
            row.append(str(packet.ip.dst))
        else:
            row.append("")
        if hasattr(packet, 'ip'):
                row.append(str(packet.ip.src))
        else:
            row.append("")
        row.append(str(packet[packet.transport_layer].srcport))
        row.append(str(packet[packet.transport_layer].dstport))
        row.append(str(packet.transport_layer))
        row.append(str(packet.captured_length))
        print(row)
        CsvWriter.writerow(row)
stop_threads = False
try:
    # thread_capture = _thread.start_new_thread(capture(cap))
    # thread_waitToStop = _thread.start_new_thread(waitToStop, ())
    # capture(cap)
    thread_waitToStop = threading.Thread(target=waitToStop, args=())
    thread_capture = threading.Thread(target=capture, args=())
    thread_waitToStop.start()
    thread_capture.start()

    thread_waitToStop.join()
    thread_capture.join()

except Exception as e:
    print(e)
