import pandas
import re

# temp = 'Cookie: navigate-user=\"" OR TRUE--%20\r\n'
# # black_list = "['OR 1 == 1', 'OR TRUE', '\', '""']"


# for i in black_list:
#     result = re.match(i, temp)
#     print(result)
data = "Nov 21, 2021 01:24:35.491601000 SE Asia Standard Time"
data = data.split(' ')
print(data)
temp = ' '.join(data[0:4]).replace(',', '')
print(str(temp))