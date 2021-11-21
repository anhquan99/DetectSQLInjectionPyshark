import pandas
import re

temp = 'Cookie: navigate-user=\"" OR TRUE--%20\r\n'
# black_list = "['OR 1 == 1', 'OR TRUE', '\', '""']"


for i in black_list:
    result = re.match(i, temp)
    print(result)