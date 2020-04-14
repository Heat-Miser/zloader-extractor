import xlrd
import argparse
import operator
import re
import os
import yara


ZLOADER_YARA = """
rule Zloader
{
    meta:
        author = "Zloader dropper"
        date = "2020-04-11"
        credit = "Hash Miser <contact-yara@heat-miser.net>"
        description = "Spot zloader xls droppers using super hidden sheet"
    strings:
         $zloader = { 53 68 65 65 74 31 85 00 12 00 ?? ?? ?? 00 02 01 0A 00 }
         $header = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        filesize < 5MB
        and $header at 0
        and $zloader
}
"""

def check_sample(filename):
    with open(filename, "rb") as f:
        binary_content = f.read()
        my_rule = yara.compile(source=ZLOADER_YARA)
        matches = my_rule.match(data=binary_content)
    return matches

def check_type(sheet):
    c = sheet.col(0)
    types = set()
    for line in c:
        if line.ctype != 0:
            types.add(line.ctype)
    if len(types) > 0:
        return list(types)[0]
    return 'z'

def manage_type_1(sheet):
    urls = []
    values = {}
    lines = []
    for col in range(sheet.ncols):
        res = ""
        for index, line in enumerate(sheet.col(col)):
            try:
                if line.ctype != 1:
                    continue
                if line.value not in values.keys():
                    values[line.value] = 1
                else:
                    values[line.value] += 1
                res += line.value
            except:
                continue
        lines.append(res)
    maxval = max(values.items(), key=operator.itemgetter(1))[0]
    if not re.match("^[a-z0-9A-Z]+$", maxval):
        maxval = ""
    for line in lines:
        line = line.replace(maxval, "")
        urls += re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line)
    return urls


def manage_type_2(sheet):
    urls = []
    for i in range(-250, 255, +1):
        for j in range(sheet.ncols):
            res = ""
            for line in sheet.col(j):
                if line.ctype == 2:
                    if line.value != "" and line.value - i >= 32 and line.value -i <= 126:
                        res += chr(int(line.value) - i)
            urls += re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', res)
    return urls


def extract_macros(filename):

    print("Extracting macros from %s" % filename)
    try:
        wb = xlrd.open_workbook(filename)
    except:
        print("ERROR: not a valid xls file")
        return []

    for sheet in wb.sheets():
        if sheet.visibility == 2:
            typ = check_type(sheet)
            if typ == 1:
                return manage_type_1(sheet)
            elif typ == 2:
                return manage_type_2(sheet)
            else:
                print("ERROR: unsupported file format")
                return []


if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description='Tries to urls from zloader xls droppers')
    PARSER.add_argument('-d', nargs='?', help="directory containing xls droppers")
    PARSER.add_argument('-f', nargs='?', help="xls dropper")
    ARGS = PARSER.parse_args()
    if not ARGS.d and not ARGS.f:
        PARSER.error("Please provide at least one file or directory")
    if ARGS.f:
        if check_sample(ARGS.f):
            results = extract_macros(ARGS.f)
            if results:
                print("Payload delivery urls found:")
                for url in results:
                    print(url)
            exit(0)
        else:
            print("ERROR: not a Zloader sample")
            exit(1)
    if ARGS.d:
        urls = []
        for root,d_names,f_names in os.walk(ARGS.d):
            for f in f_names:
                file = os.path.join(root, f)
                if check_sample(file):
                    urls += extract_macros(file)
        print("Payload delivery urls found:")
        urls = list(dict.fromkeys(urls))
        for url in urls:
            print(url)
        exit(0)


