import struct, os
import pandas as pd
from datetime import timedelta, datetime
import sys

if len(sys.argv) != 2:
	print('Please enter the right syntax')
	print('>> jumplist.py [path]')
	exit()

# hex to int
def htoi(arr):
	result = str()
	for value in arr[::-1]:
		if value == 0:
			continue
		else:
			result += hex(value).split('0x')[1]
	if result == str():
		return 0
	else:
		return	int(result,16)
# Time
def FileTime(NetworkStamp):
	if htoi(NetworkStamp) == 0:
		return [0,0,0]
	# Creation, Access, Write
	timelist = [NetworkStamp[:8],NetworkStamp[8:16],NetworkStamp[16:24]]
	resultlist = list()
	for time in timelist:
		Ftime = int(struct.unpack('<Q',time)[0])
		Epoch = divmod(Ftime - 116444736000000000, 10000000)
		resultlist.append(datetime.fromtimestamp(Epoch[0]).strftime('%Y-%m-%d %H:%M:%S'))
	return resultlist
# File Attributes
def F_AT(value):
	attributes = ['readonly','hidden','system','volume_label','directory','archive','normal','temporary','sparse_file','reparse_point','compressed','offline','not_content_indexed','encrypted','integetiry_stream','virtual']
	value = list(bin(value))[2:][::-1]
	set_value = list()
	result_attributes = list()

	for i,v in enumerate(value):
		if v == '1':
			set_value.append(i)

	for i in set_value:
		result_attributes.append(attributes[i])

	return result_attributes
# File Flags
def F_flag(value):
	flags = ['HasLinkTargetIDList','HasLinkInfo','HasName','HasRelativePath','HasWorkingDir','HasArguments','HasIconLocation','IsUnicode','ForceNoLinkInfo','HasExpString','RunInSeparateProcess','Unused1','HasDarwinID','RunAsUser','HasExpIcon','NoPidlAlias','Unused2','RunWithShimLayer','ForceNoLinkTrack','EnableTargetMetadata','DisableLinkPathTracking','DisableKnownFolderTracking','DisableKnownFolderAlias','AllowLinkToLink','UnaliasOnSave','PreferEnvironmentPath','KeepLocalIDListForUNCTarget','Unused']
	value = list(bin(value))[2:][::-1]
	set_value = list()
	result_flags = list()

	for i,v in enumerate(value):
		if v == '1':
			set_value.append(i)

	for i in set_value:
		result_flags.append(flags[i])
	
	return result_flags

def analyze(path, lnk_file):
	df = pd.DataFrame(columns=['Filename','Filesize','File Creationtime(UTC+9)','File Accesstime(UTC+9)','File Writetime(UTC+9)','Filepath'])
	df_index = 1
	for lnk_value in lnk_file:
		temp_list = list()
		try:
			with open(path+lnk_value,'rb') as jmp:
				lnk = jmp.read()

				# signature
				if hex(lnk[0]) != '0x4c':
					# print(lnk_value,'is Not link file!')
					continue

				# ShellLinkHeader
				try:
					SLH = lnk[:76]
				except Exception as e:
					print(lnk_value,">> Can't find ShellLinkHeader")
					exit()
				
				# LinkTargetIDList (76:SLH, 2:header)
				try:
					ltl_offset = htoi(lnk[76:78]) + 76 + 2
					LTL = lnk[76:ltl_offset]
				except Exception as e:
					print(lnk_value,">> Can't find LinkTargetIDList")
					exit()
				
				# LinkInfo
				try:
					lif_offset = htoi(lnk[ltl_offset:ltl_offset+4]) + ltl_offset
					LIF = lnk[ltl_offset:lif_offset]
				except Exception as e:
					print(lnk_value,">> Can't find LinkInfo")
					exit()

				# StringData
				try:
					STRD_entry = lnk[lif_offset:lif_offset+2]
				except Exception as e:
					print(lnk_value,'>>',e)
				size = htoi(SLH[52:56])
				filetime = FileTime(SLH[28:52])	
				# DosDateTime과 오차가 있지만 unpack에 어려움이 있어 차후 추가

				file_attributes_value = htoi(LTL[14:16])
				file_attributes_list = F_AT(file_attributes_value)

				fileflags_value = htoi(SLH[20:24])
				fileflags_list = F_flag(fileflags_value)

				temp_list.append(lnk_value)
				temp_list.append(size)			
				temp_list.append(filetime[0])
				temp_list.append(filetime[1])
				temp_list.append(filetime[2])


				try:
					# -1은 LinkInfo 때문
					for i in range(0,fileflags_list.index('HasWorkingDir')-1):
						offset = htoi(STRD_entry)
						offset = lif_offset+offset*2
						# string - 2byte
						STRD_entry = lnk[offset+2:offset+4]

					filepath = ''.join(list(lnk[offset+4:offset+4+htoi(STRD_entry)*2].decode())[0::2])
					temp_list.append(filepath)
				except Exception as e:
					IDList0_size = htoi(LTL[2:4])
					IDList1_size = htoi(LTL[IDList0_size+2:IDList0_size+4])
					IDList1_entry = IDList0_size+2
					folder_path = LTL[IDList1_entry+3:IDList1_entry+IDList1_size]
					#folder_path = str(LTL[IDList1_entry+3:IDList1_entry+IDList1_size]).split('\\x00')[0]
					if htoi(folder_path) == 0:
						folder_path == None
						print(folder_path)
					else:
						try:
							folder_path = folder_path.decode('cp1252')
						except Exception as e:
							folder_path = "Can't find path"
					temp_list.append(folder_path)

			df.loc[df_index] = temp_list
			df_index += 1
		
		except Exception as e:
			print(lnk_value,'>>',e)
		del temp_list
	return df

def main():
	lnk_folder = list()
	lnk_file = list()
	auto = pd.DataFrame()
	custom = pd.DataFrame()

	for dirpath, dirnames, filenames in os.walk(sys.argv[1]):
		lnk_folder.append(dirnames)
		lnk_file.append(filenames)

	auto_path = sys.argv[1]+'\\'+'AutomaticDestinations\\'
	auto_file = lnk_file[1]

	custom_path = sys.argv[1]+'\\'+'CustomDestinations\\'
	custom_file = lnk_file[2]
	
	# auto, custom은 jumplister로 분석
	# if 'AutomaticDestinations' in lnk_folder[0]:
	# 	auto = analyze(auto_path,auto_file)
	# if 'CustomDestinations' in lnk_folder[0]:
	# 	custom = analyze(custom_path,custom_file)
	others = analyze(sys.argv[1]+'\\',lnk_file[0])

	others.to_csv('LNK.csv',index=False)

main()