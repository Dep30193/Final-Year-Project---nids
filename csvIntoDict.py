import csv
import pprint
def beta():
    dict = []

    reader = csv.DictReader(open('/home/san/Desktop/pattern.csv', 'r'))
    for row in reader:
         dict.append(row)
    pprint.pprint(dict)

def extract_pattern():
    list = []
    # example:: wordFreqDic.update( {'before' : 23} )
    with open('/home/san/Desktop/pattern.csv', 'r') as file:
        reader = csv.reader(file, delimiter=',')
        for row in reader:  # each line
            # patt = row[0]    # specific col
            list.append(row)
        return list

extract_pattern()


