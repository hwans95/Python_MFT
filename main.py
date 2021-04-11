from header import flags_header, dir_check, flags, name_type, file_open, big_to_little, timestamp_change, filename_change, creat_csv, ads_check
from attr import std, fna
from sa import sa_

def mft_parsing(data,num):
    mft_signature = bytes(b'FILE')
    attr_id_list = [16,32,48,64,80,96,112,128] #x10 x20 x30 x40 x50 x60 x70 x80
    attr_header = 24 # Resident
    count = 0
    print(num)
    
    if mft_signature == data[0:4] and data[48:50] == data[1022:1024]: # 파일 시그니쳐 및 fixup 확인
        header_LogfileSeqNum = int.from_bytes(data[8:16], byteorder='little', signed=True)
        header_SeqNum = int.from_bytes(data[16:18], byteorder='little', signed=True)
        header_HardLinkCount = int.from_bytes(data[18:20], byteorder='little', signed=True)
        header_FirstAttrOffset = int.from_bytes(data[20:22], byteorder='little', signed=True)
        header_Flags = int.from_bytes(data[22:24], byteorder="little", signed=True)
        header_MftUseSize = int.from_bytes(data[24:28], byteorder='little', signed=True)
        header_BaseRecordFileReference = int.from_bytes(data[32:40], byteorder='little', signed=True)
        
        #if문을 통해서 하나의 리스트 안에 임의의 경우의 수 최대 값인 10개정도를 if문으로 작성 (MFT entry 최대크기인 1024 감안)
        mft_AttrList = []
        attrsize_1= int.from_bytes(data[header_FirstAttrOffset+4:header_FirstAttrOffset+8], byteorder="little", signed=True)
        attr_1 = data[header_FirstAttrOffset:header_FirstAttrOffset+attrsize_1]
        mft_AttrList.append(attr_1)
        
        if header_MftUseSize >= len(mft_AttrList[0]):
            attrsize_2 = int.from_bytes(data[header_FirstAttrOffset+attrsize_1+4:header_FirstAttrOffset+attrsize_1+8], byteorder="little", signed=True)
            attr_2 = data[header_FirstAttrOffset+attrsize_1:header_FirstAttrOffset+attrsize_1+attrsize_2]
            mft_AttrList.append(attr_2)
            if header_MftUseSize >= len(mft_AttrList[0]+mft_AttrList[1]):
                attrsize_3 = int.from_bytes(data[header_FirstAttrOffset+attrsize_1+attrsize_2+4:header_FirstAttrOffset+attrsize_1+attrsize_2+8], byteorder="little", signed=True)
                attr_3 = data[header_FirstAttrOffset+attrsize_1+attrsize_2:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3]
                mft_AttrList.append(attr_3)
                if header_MftUseSize >= len(mft_AttrList[0]+mft_AttrList[1]+mft_AttrList[2]):
                    attrsize_4 = int.from_bytes(data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+4:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+8], byteorder="little", signed=True)
                    attr_4 = data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4]
                    mft_AttrList.append(attr_4)
                    if header_MftUseSize >= len(mft_AttrList[0]+mft_AttrList[1]+mft_AttrList[2]+mft_AttrList[3]):
                        attrsize_5 = int.from_bytes(data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+4:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+8], byteorder="little", signed=True)
                        attr_5 = data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5]
                        mft_AttrList.append(attr_5)
                        if header_MftUseSize >= len(mft_AttrList[0]+mft_AttrList[1]+mft_AttrList[2]+mft_AttrList[3]+mft_AttrList[4]):
                            attrsize_6 = int.from_bytes(data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+4:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+8], byteorder="little", signed=True)
                            attr_6 = data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6]
                            mft_AttrList.append(attr_6)
                            if header_MftUseSize >= len(mft_AttrList[0]+mft_AttrList[1]+mft_AttrList[2]+mft_AttrList[3]+mft_AttrList[4]+mft_AttrList[5]):
                                attrsize_7 = int.from_bytes(data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+4:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+8], byteorder="little", signed=True)
                                attr_7 = data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+attrsize_6+attrsize_7]
                                mft_AttrList.append(attr_7)
                                if header_MftUseSize >= len(mft_AttrList[0]+mft_AttrList[1]+mft_AttrList[2]+mft_AttrList[3]+mft_AttrList[4]+mft_AttrList[5]+mft_AttrList[6]):
                                    attrsize_8 = int.from_bytes(data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+attrsize_7+4:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+attrsize_7+8], byteorder="little", signed=True)
                                    attr_8 = data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+attrsize_7:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+attrsize_6+attrsize_7+attrsize_8]
                                    mft_AttrList.append(attr_8)
                                    if header_MftUseSize >= len(mft_AttrList[0]+mft_AttrList[1]+mft_AttrList[2]+mft_AttrList[3]+mft_AttrList[4]+mft_AttrList[5]+mft_AttrList[6]+mft_AttrList[7]):
                                        attrsize_9 = int.from_bytes(data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+attrsize_7+attrsize_8+4:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+attrsize_7+attrsize_8+8], byteorder="little", signed=True)
                                        attr_9 = data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+attrsize_7+attrsize_8:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+attrsize_6+attrsize_7+attrsize_8+attrsize_9]
                                        mft_AttrList.append(attr_9)
                                        if header_MftUseSize >= len(mft_AttrList[0]+mft_AttrList[1]+mft_AttrList[2]+mft_AttrList[3]+mft_AttrList[4]+mft_AttrList[5]+mft_AttrList[6]+mft_AttrList[7]):
                                            attrsize_10 = int.from_bytes(data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+attrsize_7+attrsize_8+attrsize_9+4:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+attrsize_7+attrsize_8+attrsize_9+8], byteorder="little", signed=True)
                                            attr_10 = data[header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+attrsize_7+attrsize_8+attrsize_9:header_FirstAttrOffset+attrsize_1+attrsize_2+attrsize_3+attrsize_4+attrsize_5+attrsize_6+attrsize_6+attrsize_7+attrsize_8+attrsize_9+attrsize_10]
                                            
        # CSV 저장 로직
        not_ = " "
        f = open("C:\\Users\\hwanj95\\Desktop\\2021\\sample.csv", 'a', encoding='utf-8', newline='')
        wr = csv.writer(f)
        count = 0
        std_total = []
        fna_total = []
        for x in mft_AttrList:
            if 16 == int.from_bytes(x[0:4], byteorder="little", signed=True):
                std_total.append(std(x))
            elif 48 == int.from_bytes(x[0:4], byteorder="little", signed=True):
                fna_total.append(fna(x))
            elif 128 == int.from_bytes(x[0:4], byteorder="little", signed=True):
                count += 1
            else: pass
    
        if len(std_total) == 1 and len(fna_total) == 0: #std 1개 존재 fna 없음
                wr.writerow([num, flags_header(header_Flags), header_SeqNum, header_HardLinkCount,
                    not_, not_, not_, not_,
                    ads_check(count), not_, dir_check(header_Flags), std_total[0][3], 
                    not_, not_, std_total[0][0], std_total[0][1],
                    std_total[0][2], not_, not_, not_,
                    header_BaseRecordFileReference, header_LogfileSeqNum, std_total[0][6], std_total[0][7],
                    std_total[0][8], std_total[0][9]])
                f.close()
                return 0
        elif len(std_total) == 1 and len(fna_total) == 1: # std 1개 존재 fna 1개 존재
            wr.writerow([num, flags_header(header_Flags), header_SeqNum, header_HardLinkCount,
                        fna_total[0][0], fna_total[0][1], fna_total[0][8], not_,
                        ads_check(count), fna_total[0][5], dir_check(header_Flags), std_total[0][3],
                        fna_total[0][6], fna_total[0][7], std_total[0][0], std_total[0][1],
                        std_total[0][2], fna_total[0][2], fna_total[0][3], fna_total[0][4],
                        header_BaseRecordFileReference, header_LogfileSeqNum, std_total[0][6], std_total[0][7],
                        std_total[0][8], std_total[0][9]])
            f.close()
            return 0
        elif len(std_total) == 1 and len(fna_total) == 2: # std 1개 존재 fna 2개 존재
            wr.writerow([num, flags_header(header_Flags), header_SeqNum, header_HardLinkCount,
                        fna_total[0][0], fna_total[0][1], fna_total[0][8], fna_total[1][8],
                        ads_check(count),fna_total[0][5], dir_check(header_Flags), std_total[0][3],
                        fna_total[0][6],fna_total[0][7], std_total[0][0], std_total[0][1],
                        std_total[0][2],fna_total[0][2], fna_total[0][3], fna_total[0][4],
                        header_BaseRecordFileReference, header_LogfileSeqNum, std_total[0][6], std_total[0][7],
                        std_total[0][8], std_total[0][9]])
            f.close()
            return 0
        elif len(std_total) == 0 and len(fna_total) == 1: # std 없음 fna 1개 존재
            wr.writerow([num, flags_header(header_Flags), header_SeqNum, header_HardLinkCount,
                        fna_total[0][0], fna_total[0][1], fna_total[0][8], not_,
                        ads_check(count), fna_total[0][5], dir_check(header_Flags), not_,
                        fna_total[0][6],fna_total[0][7], not_, not_,
                        not_, fna_total[0][2], fna_total[0][3], fna_total[0][4],
                        header_BaseRecordFileReference, header_LogfileSeqNum, not_, not_, not_, not_])
            f.close()
            return 0
        elif len(std_total) == 0 and len(fna_total) == 2: # std 없음 fna 2개 존재
            wr.writerow([num, flags_header(header_Flags), header_SeqNum, header_HardLinkCount, 
                        fna_total[0][0], fna_total[0][1], fna_total[0][8], fna_total[1][8],
                        ads_check(count),fna_total[0][5], dir_check(header_Flags), not_,
                        fna_total[0][6],fna_total[0][7], not_, not_,
                        not_, fna_total[0][2], fna_total[0][3], fna_total[0][4],
                        header_BaseRecordFileReference, header_LogfileSeqNum, not_, not_, not_, not_])
            f.close()
            return 0
        else: return 0
        
    else: return 0 # entry header check 


if __name__ == '__main__':
    import os
    from datetime import datetime,timedelta 
    import csv
    import binascii
    import time
    import pandas as pd
    
    data = file_open()
    entry_count = len(data)//1024 # MFT Entry 개수
    start = 0 #엔트리 시작
    finish = 1024 #엔트리 끝
    i = 0
    mft_size = len(data)
    creat_csv()
    
    while i <= entry_count:
        mft_entry = data[start:finish]
        if mft_parsing(mft_entry,i) == 0:
            pass
        if i == entry_count:
            break
        start += 1024
        finish += 1024
        i += 1
    
