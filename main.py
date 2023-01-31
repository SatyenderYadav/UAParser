import codecs
import sys
import re
import itertools
import datetime
import struct
import prettytable
import argparse
import operator
import magic

def read_reg(regName):
	regFile = codecs.open (regName, encoding="utf_16")
	reg = regFile.read()
	regFile.close()
	return reg

def check_filetype(regName):
	return(magic.from_file(regName))

def convert_filetime(file_time):
	return((datetime.datetime (1601, 1, 1) + datetime.timedelta(seconds=file_time/10000000)).strftime('%Y-%m-%d %H:%M:%S:%f'))


def split_on_empty_lines(s):
    blank_line_regex = r"(?:\r?\n){2,}"
    return re.split(blank_line_regex, s.strip())


def UserAssistHexParser(hexdata):
	HexToData = ""
	ConvertedHex  = "".join(x.strip() for x in hexdata.decode().splitlines()).replace("\\","").replace(",","")
	bytehex = bytes(bytearray.fromhex(ConvertedHex))
	RunCount = (struct.unpack("I",bytehex[4:8]))[0]
	HexToData += str(RunCount) + ","
	FocusCount = (struct.unpack("I",bytehex[8:12]))[0]
	HexToData += str(FocusCount) + ","
	FocusCountTime = (struct.unpack("I",bytehex[12:16]))[0]
	HexToData += str(FocusCountTime) + ","
	fileModifiedTimeEpoch = (struct.unpack("q",bytehex[60:68]))[0]
	fileModifiedTime = str(convert_filetime(fileModifiedTimeEpoch))
	if fileModifiedTime.__contains__("1601-01-01"):
		fileModifiedTime = ''
	HexToData += str(fileModifiedTime) 
	return HexToData


def rot_13(name):
	return codecs.decode(name,"rot_13")

def banner():
	print("\t\t\t\t\t\t\u001b[1m\u001b[38;5;8m  ===========================================================\u001b[37;1m")
	print("\t\t\t\t\t\t██╗░░░██╗░█████╗░██████╗░░█████╗░██████╗░░██████╗███████╗██████╗░")
	print("\t\t\t\t\t\t██║░░░██║██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗")
	print("\t\t\t\t\t\t██║░░░██║███████║██████╔╝███████║██████╔╝╚█████╗░█████╗░░██████╔╝")
	print("\t\t\t\t\t\t██║░░░██║██╔══██║██╔═══╝░██╔══██║██╔══██╗░╚═══██╗██╔══╝░░██╔══██╗")
	print("\t\t\t\t\t\t╚██████╔╝██║░░██║██║░░░░░██║░░██║██║░░██║██████╔╝███████╗██║░░██║")
	print("\t\t\t\t\t\t░╚═════╝░╚═╝░░╚═╝╚═╝░░░░░╚═╝░░╚═╝╚═╝░░╚═╝╚═════╝░╚══════╝╚═╝░░╚═╝")
	print("\t\t\t\t\t\t\u001b[1m\u001b[38;5;8m  ===========================================================\u001b[37;1m")
	print("\033[0m")

def show_Result(finalOutput):
	banner()
	headers=['ClassID', 'Path', 'Run Count', 'Focus Count', 'Focus Count Time', 'File Modified Time [ UTC ]']
	table = prettytable.PrettyTable(headers)
	table.border = True
	table.vrules = 1
	table.hrules = 1
	table._max_width = {"ClassID" : 40, "Path" : 55, "Run Count" : 5, "Focus Count" : 5, "Focus Count Time" : 10, "File Modified Time" : 20}
	for data in finalOutput:
		table.add_row(data)
	print(table.get_string(sort_key=operator.itemgetter(1, 0), sortby="Path"))


def main(regName):
	IncludedType = ["MS Windows registry file, NT/2000 or above", "Windows Registry little-endian text (Win2K or above)" ]
	if check_filetype(regName).__contains__(IncludedType[1]):
		RegistryKeyList = split_on_empty_lines(read_reg(regName))
		UserAssistKeys = {}
		finalOutput = []

		for RegistryValue in RegistryKeyList:
			if RegistryValue.__contains__('HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist'):
				if RegistryValue.__contains__('Count'):
					TempKeyValue = RegistryValue.split("\r\n",1)
					if len(TempKeyValue) == 1:
						TempKeyValue.append('')
					UserAssistKeys[TempKeyValue[0]] = TempKeyValue[1]
	
		for keys, values in UserAssistKeys.items():	
			ClassID = keys.split("\\")[::-1][1]	
			if values == '':
				pass
			else:
				Subkeys = values.split('\r\n"')
				for entries in Subkeys:
					dataToAppend = []
					dataToAppend.append(ClassID)
					entriesParts = entries.split("=hex:")
					FullName = entriesParts[0]
					HexData = entriesParts[1]
					Path = rot_13(FullName).replace("\\\\","\\")
					if Path.__contains__("UEME"):
						pass
					else:
						entriesDetails = UserAssistHexParser(HexData.encode()).split(",")
						dataToAppend.append(Path)
						dataToAppend.extend(entriesDetails)
					if len(dataToAppend) == 1 :
						pass
					else:
						finalOutput.append(dataToAppend)

		show_Result(finalOutput)
	else:
		banner()
		if check_filetype(regName).__contains__(IncludedType[0]):
			print(f"Curently tool only support the {IncludedType[1]} soon will add the support to parse the NTUSER.DAT")
		else:
			print(f"This is not a proper {IncludedType[1]} file")

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("-f","--file", type=str, required=True ,help="NT User Registry Text File")
	args = parser.parse_args()
	main(args.file)
