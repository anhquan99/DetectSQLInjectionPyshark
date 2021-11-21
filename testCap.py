import pandas

pdf = pandas.read_csv("ResultDirectCapture.csv", header=None)
temp = pdf.itertuples(index = True, name = None)
for i in pdf.index:
    print(i)