import pyshark
import csv
import threading
import time
from os.path import exists
import sys


def getInfo(pck):
    if pck.highest_layer == 'DATA':
            if hasattr(pck.layers[2], "length"):
                return '{0} > {1} LEN={2}'.format(pck.layers[2].dstport, pck.layers[2].srcport, pck.layers[2].length)
            else:
                return '{0} > {1}'.format(pck.layers[2].dstport, pck.layers[2].srcport)
    elif pck.highest_layer == 'TCP':
        flag = getFlag(pck)
        if 'ACK' in flag:
            return '{0} > {1} [{2}] Seq={3} Ack={4} Win={5} LEN={6}'.format(pck.layers[2].dstport, pck.layers[2].srcport, getFlag(pck), pck.layers[2].seq, pck.layers[2].ack, pck.layers[2].window_size, pck.layers[2].len)
        else:
            return '{0} > {1} [{2}] Seq={3} Win={4} LEN={5}'.format(pck.layers[2].port, pck.layers[2].srcport, getFlag(pck), pck.layers[2].seq, pck.layers[2].window_size, pck.layers[2].len)
    elif pck.highest_layer == 'DATA-TEXT-LINES':
        return str(pck.layers[-2])
    else:
            return str(pck.layers[-1])


def getFlag(pck):
    flag = int(pck.layers[2].flags, 16)
    flags = []
    if flag & 0b00000001:
        flags.append('FIN')
    if flag & 0b00000010:
        flags.append('SYN')
    if flag & 0b00000100:
        flags.append('RST')
    if flag & 0b00001000:
        flags.append('PUS')
    if flag & 0b00010000:
        flags.append('ACK')
    if flag & 0b00100000:
        flags.append('URG')
    if flag & 0b01000000:
        flags.append('ECN')
    if flag & 0b10000000:
        flags.append('CWR')
    return ', '.join(flags)
def capture(user_interface):
    try:
        cap = pyshark.LiveCapture(interface=user_interface)    
        for packet in cap.sniff_continuously():
            writePacket(packet)
            global stop_threads
            if stop_threads:
                break    
        cap.close()
    except Exception as e:
        print(str(e))
    finally:
        cap.close()
def waitToStop():
    input()
    global stop_threads
    stop_threads = True  
def writePacket(packet):
    try:
        with open('ResultDirectCapture.csv', 'a', encoding='UTF8') as csvfile:
            CsvWriter = csv.writer(csvfile, delimiter=";")
            row = []
            row.append(str(packet.frame_info.time))
            x = str(packet.frame_info._all_fields['frame.protocols']).split(':')
            if hasattr(packet, 'ip') and packet.ip is not None:
                if hasattr(packet.ip, 'dst') and packet.ip.dst is not None :
                    row.append(str(packet.ip.dst))
                else:
                    row.append("None")
                if hasattr(packet.ip, 'src') and packet.ip.src is not None :
                    row.append(str(packet.ip.src))
                else:
                    row.append("None")

            if hasattr(packet, 'transport_layer')  and packet.transport_layer is not None:
                if hasattr(packet[packet.transport_layer], 'srcport') and packet[packet.transport_layer].srcport is not None :
                    row.append(str(packet[packet.transport_layer].srcport))
                else:
                    row.append("None")
                if hasattr(packet[packet.transport_layer], 'dstport') and packet[packet.transport_layer].dstport is not None:
                    row.append(str(packet[packet.transport_layer].dstport))
                else:
                    row.append("None")
            if x[len(x)-1] != 'data' and x[len(x)-1] != 'data-text-lines' :
                    row.append(x[len(x)-1])
            else:
                row.append(x[len(x)-2])
            if hasattr(packet, 'captured_length') and packet.captured_length is not None:
                    row.append(str(packet.captured_length))
            else:
                row.append("None")
            getInfoStr = getInfo(packet).replace('\n', ' ').replace('\r', '').replace(';', '')
            row.append(getInfoStr)
            print(row)     
            CsvWriter.writerow(row)
            csvfile.close()
    except AttributeError as e:
        print("Packet attribute not found")
stop_threads = False
def run(user_interface):
    try:
        # thread_capture = _thread.start_new_thread(capture(cap))
        # thread_waitToStop = _thread.start_new_thread(waitToStop, ())
        # capture(cap)
        thread_waitToStop = threading.Thread(target=waitToStop, args=())
        thread_capture = threading.Thread(target=capture, args=(user_interface,))
        thread_waitToStop.start()
        thread_capture.start()

        thread_waitToStop.join()
        thread_capture.join()

    except Exception as e:
        print(e)
if len(sys.argv) < 2 :
    print("Usage: DirectCapture.py [interface]")
elif sys.argv[1] == '-h' or sys.argv[1] == 'help':
    print("Usage: DirectCapture.py [interface]")
else:
    print(sys.argv[1])
    run(sys.argv[1])