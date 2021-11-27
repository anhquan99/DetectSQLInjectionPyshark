import pandas
import re
from urllib.parse import unquote
import pyshark
# temp = 'Cookie: navigate-user=\"" OR TRUE--%20\r\n'
# # black_list = "['OR 1 == 1', 'OR TRUE', '\', '""']"


# for i in black_list:
#     result = re.match(i, temp)
#     print(result)

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
# strTemp = "Nov 27, 2021 22:30:25.867651000 SE Asia Standard Time;192.168.111.132;192.168.111.136;80;42707;http;71;Layer HTTP: 	HTTP/1.1 200 OK\r\n 	Expert Info (Chat/Sequence): HTTP/1.1 200 OK\r\n 	HTTP/1.1 200 OK\r\n 	Severity level: Chat 	Group: Sequence 	Response Version: HTTP/1.1 	Status Code: 200 	Status Code Description: OK 	Response Phrase: OK 	Date: Sat, 27 Nov 2021 15:30:27 GMT\r\n 	Server: Apache/2.4.29 (Ubuntu)\r\n 	Set-Cookie: NVSID_8a0e81e4=10aab06rmo50tvq9eehgblf2a5 path=/\r\n 	Cache-Control: no-store, no-cache, must-revalidate\r\n 	Transfer-Encoding: chunked\r\n 	Content-Type: application/json\r\n 	HTTP response 1/1 	Time since request: 0.011477000 seconds 	Request in frame: 48 	Request URI: http://192.168.111.136/navigate/navigate_upload.php?session_id=10aab06rmo50tvq9eehgblf2a5&engine=picnik&id=../../../navigate_info.php 	Chunk size: 0 octets 	File Data: 0 bytes 	\r\n 	HTTP chunked response 	End of chunked encoding 	\r\n 	Expires: Thu, 19 Nov 1981 08:52:00 GMT\r\n 	Pragma: no-cache\r\n 	Set-Cookie: NVSID_8a0e81e4=10aab06rmo50tvq9eehgblf2a5 expires=Sat, 27-Nov-2021 16:30:27 GMT Max-Age=3600 path=/ domain=192.168.111.136\r\n 	Set-Cookie: PHPSESSID=10aab06rmo50tvq9eehgblf2a5 expires=Sat, 27-Nov-2021 16:30:27 GMT Max-Age=3600 path=/ domain=192.168.111.136\r\n"
# strTemp = unquote(strTemp).split(';')
# strTemp = strTemp[len(strTemp)-1].split("\\n")
# temp = [s for s in strTemp if "HTTP/1.1 200 OK" in s and "navigate/navigate_upload.php" in s]
# print(temp)
# # for i in black_list:
# #     result = re.match(i, strTemp)
# #     if result != None:
# #         print("True")


cap = pyshark.LiveCapture(interface="VMware")
for packet in cap.sniff_continuously():
    if packet.highest_layer.lower() == "data-text-lines":
        x = str(packet.frame_info._all_fields['frame.protocols']).split(':')
        print(x)
