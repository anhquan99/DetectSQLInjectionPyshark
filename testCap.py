import pandas
import re
from urllib.parse import unquote

# temp = 'Cookie: navigate-user=\"" OR TRUE--%20\r\n'
# # black_list = "['OR 1 == 1', 'OR TRUE', '\', '""']"


# for i in black_list:
#     result = re.match(i, temp)
#     print(result)

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
strTemp = "Nov 23, 2021 00:26:08.307953000 SE Asia Standard Time;192.168.111.136;192.168.111.132;43326;80;http;441;Layer HTTP: 	POST /navigate/login.php HTTP/1.1\r\n 	Expert Info (Chat/Sequence): POST /navigate/login.php HTTP/1.1\r\n 	POST /navigate/login.php HTTP/1.1\r\n 	Severity level: Chat 	Group: Sequence 	Request Method: POST 	Request URI: /navigate/login.php 	Request Version: HTTP/1.1 	Content-Length: 0\r\n 	Content length: 0 	Cache-Control: no-cache\r\n 	Cookie: navigate-user=low%27%29%29%20AND%203892%3D3451%20AND%20%28%28%27YLRh%27%3D%27YLRh\r\n 	Cookie pair: navigate-user=low%27%29%29%20AND%203892%3D3451%20AND%20%28%28%27YLRh%27%3D%27YLRh 	User-Agent: sqlmap/1.5.2#stable (http://sqlmap.org)\r\n 	Host: 192.168.111.136\r\n 	Accept: */*\r\n 	Accept-Encoding: gzip,deflate\r\n 	Content-Type: application/x-www-form-urlencoded charset=utf-8\r\n 	Connection: close\r\n 	Full request URI: http://192.168.111.136/navigate/login.php 	HTTP request 1/1 	\r\n "
strTemp = unquote(strTemp).split(';')
print(strTemp)
# for i in black_list:
#     result = re.match(i, strTemp)
#     if result != None:
#         print("True")