import os
from datetime import datetime,timedelta 
import csv
import binascii
import time

def ads_check(count):
    ads_1 = "Have"
    ads_2 = " "
    if count == 0 or count == 1: return ads_2
    else: return ads_1


def flags_header(sam_):
    text = ["TRUE","NOT USE"]
    if sam_ == 1 or 3:
        return text[0]
    else: return text[1]
    
    
def dir_check(sam):
    text_ = ["TRUE","FALSE"]
    if sam == 3:
        return text_[0]
    else: return text_[1]


def flags(sample_): #수정필요
    f_1 = [1,'Read Only']
    f_2 = [2,'Hidden'] 
    f_3 = [4,'System'] 
    f_4 = [32,'Archive']
    f_5 = [64,'Device'] 
    f_6 = [128,'Normal']
    f_7 = [256,'Temporary'] 
    f_8 = [512,'Sparse'] 
    f_9 = [1024,'Reparse_point'] 
    f_10 = [2048,'Compressed'] 
    f_11 = [4096,'Offline'] 
    f_12 = [8192,'NotContentIndex'] 
    f_13 = [16384,'Encrypted'] 
    f_14 = [6,'Hidden|system'] 
    f_15 = 'None'
    f_16 = [268435456,'Directory']
    f_17 = [536870912,'IndexView']
    f_18 = [536870918,'Hidden+System+IndexView']
    f_19 = [268435462,'Hidden+System+Directory']
    f_20 = [8224,'Archive+NotContentIndex']
    f_21 = [2080,'Archive+Compressed']
    f_22 = [10272,'Archive+Compressed+NotContentIndex']
    f_23 = [1056,'Archive+Reparse_point']
    f_24 = [544,'Archive+Sparse']
    f_25 = [8736,'Archive+Sparse+NotContentIndex']
    f_26 = [1568,'Archive+Sparse+Reparse_point']
    f_27 = [288,'Archive+Temporary']
    f_28 = [2336,'Archive+Temporary+Compressed']
    f_29 = [10240,'Compressed+NotContentIndex']
    f_30 = [34,'Hidden+Archive']
    f_31 = [8226,'Hidden+Archive+NotContentIndex']
    f_32 = [8194,'Hidden+NotContentIndex']
    f_33 = [38,'Hidden+System+Archive']
    f_34 = [8230,'Hidden+System+Archive+NotContentIndex']
    f_35 = [518,'Hidden+System+Sparse']
    f_36 = [9222,'Hidden+System+Reparse_point+NotContentIndex']
    f_37 = [268443648,'NotContentIndex+Directory']
    f_38 = [33,'Read Only+Archive']
    f_39 = [3,'Read Only+Hidden']
    f_40 = [35,'Read Only+Hidden+Archive']
    f_41 = [8195,'Read Only+Hidden+NotContentIndex']
    f_42 = [39,'Read Only+Hidden+System+Archive']
    f_43 = [8193,'Read Only+NotContentIndex']
    f_44 = [5,'Read Only+System']
    f_45 = [37,'Read Only+System+Archive']
    f_46 = [36,'System+Archive']
    f_47 = [8228,'System+Archive+NotContentIndex']
    f_48 = [9764,'System+Archive+Sparse+Reparse_point+NotContentIndex']
    f_49 = [268435460,'System+Directory']
    f_50 = [8196,'System+NotContentIndex']
    
    if sample_ == f_1[0]: return f_1[1]
    elif sample_ == f_2[0]: return f_2[1]
    elif sample_ == f_3[0]: return f_3[1]
    elif sample_ == f_4[0]: return f_4[1]
    elif sample_ == f_5[0]: return f_5[1]
    elif sample_ == f_6[0]: return f_6[1]
    elif sample_ == f_7[0]: return f_7[1]
    elif sample_ == f_8[0]: return f_8[1]
    elif sample_ == f_9[0]: return f_9[1]
    elif sample_ == f_10[0]: return f_10[1]
    elif sample_ == f_11[0]: return f_11[1]
    elif sample_ == f_12[0]: return f_12[1]
    elif sample_ == f_13[0]: return f_13[1]
    elif sample_ == f_14[0]: return f_14[1]
    elif sample_ == f_16[0]: return f_16[1]
    elif sample_ == f_17[0]: return f_17[1]
    elif sample_ == f_18[0]: return f_18[1]
    elif sample_ == f_19[0]: return f_19[1]
    elif sample_ == f_20[0]: return f_20[1]
    elif sample_ == f_21[0]: return f_21[1]
    elif sample_ == f_22[0]: return f_22[1]
    elif sample_ == f_23[0]: return f_23[1]
    elif sample_ == f_24[0]: return f_24[1]
    elif sample_ == f_25[0]: return f_25[1]
    elif sample_ == f_26[0]: return f_26[1]
    elif sample_ == f_27[0]: return f_27[1]
    elif sample_ == f_28[0]: return f_28[1]
    elif sample_ == f_29[0]: return f_29[1]
    elif sample_ == f_30[0]: return f_30[1]
    elif sample_ == f_31[0]: return f_31[1]
    elif sample_ == f_32[0]: return f_32[1]
    elif sample_ == f_33[0]: return f_33[1]
    elif sample_ == f_34[0]: return f_34[1]
    elif sample_ == f_35[0]: return f_35[1]
    elif sample_ == f_36[0]: return f_36[1]
    elif sample_ == f_37[0]: return f_37[1]
    elif sample_ == f_38[0]: return f_38[1]
    elif sample_ == f_39[0]: return f_39[1]
    elif sample_ == f_40[0]: return f_40[1]
    elif sample_ == f_41[0]: return f_41[1]
    elif sample_ == f_42[0]: return f_42[1]
    elif sample_ == f_43[0]: return f_43[1]
    elif sample_ == f_44[0]: return f_44[1]
    elif sample_ == f_45[0]: return f_45[1]
    elif sample_ == f_46[0]: return f_46[1]
    elif sample_ == f_47[0]: return f_47[1]
    elif sample_ == f_48[0]: return f_48[1]
    elif sample_ == f_49[0]: return f_49[1]
    elif sample_ == f_50[0]: return f_50[1]
    else: return f_15

def name_type(type_):
    type_list = ['POSIX','Windows','Dos','DosWindows','Error']
    if type_ == 0:
        return type_list[0]
    elif type_ == 1:
        return type_list[1]
    elif type_ == 2:
        return type_list[2]
    elif type_ == 3:
        return type_list[3]
    else: return type_list[4]

def file_open():
    data = bytearray()
    #file = "mftcheck1"
    file = "MFT.Copy0"
    #file = "attrfnafna"
    #file = "attrfna"
    #file = "attlistfna"
    #file = "start_fna"
    #file = "MFTz"
    #file = "MFTcopy1"
    #file = "attlist_MFT"
    with open(file, 'rb') as f:
        data = f.read()
    return data

def big_to_little(da): # 빅엔디안 hex값 데이터를 리틀엔디안 int 값 데이터로 변경
    reverse = int.from_bytes(da, byteorder='little', signed=True)
    return reverse

def timestamp_change(time):
    hex_to_int = int.from_bytes(time, byteorder='little', signed=True)
    us = hex_to_int / 10.
    change_time = datetime(1601,1,1) + timedelta(microseconds=us)
    return change_time

def filename_change(name):
    f1 = int.from_bytes(name, byteorder='little',signed=True)
    err = "None"
    if f1 <= 0:
        return err
    else:
        file_ = []
        for i in name:
            if hex(i) != '0x0':
                file_.append(chr(i))
                file_name = "".join(file_)
        return file_name

def creat_csv():
    f = open("C:\\Users\\hwanj95\\Desktop\\2021\\sample.csv", 'w', encoding='utf-8', newline='')
    wr = csv.writer(f)
    wr.writerow(["EntryNumber","InUse","HEADER_SequenceNum","HEADER_LinkCount","FNA_ParentNum","FNA_Parent_SeqNum","FileName","FileName2","ADS","FileSize","Directory","STD_Flags","FNA_Flags","FNA_NameType","STD_CreatTime","STD_modifiedTime","STD_LatsAccessTime","FNA_CreatTime","FNA_modifiedTime","FNA_LatsAccessTime","HEADER_BaseRecordFileReference","header_LogfileSeqNum","STD_ClassId","STD_OwnerId","STD_SecurityId","STD_UpdateSeqNum"])
    f.close()