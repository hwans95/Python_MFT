from header import flags_header, dir_check, flags, name_type, file_open, big_to_little, timestamp_change, filename_change, creat_csv, ads_check
attr_header = 24

def std(temp):
    if int.from_bytes(temp[0:4], byteorder="little", signed=True) == 16:
        std_creatTime = timestamp_change(temp[attr_header:attr_header+8])
        std_modifiedTime = timestamp_change(temp[attr_header+8:attr_header+16])
        std_lastaccessTime = timestamp_change(temp[attr_header+(8*3):attr_header+(8*4)])
        std_flags = flags(int.from_bytes(temp[attr_header+32:attr_header+36], byteorder="little", signed=True))
        std_vermax = int.from_bytes(temp[attr_header+36:attr_header+40], byteorder="little", signed=True)
        std_vernum = int.from_bytes(temp[attr_header+40:attr_header+44], byteorder="little", signed=True)
        std_classid = int.from_bytes(temp[attr_header+44:attr_header+48], byteorder="little", signed=True)
        std_ownerid = int.from_bytes(temp[attr_header+48:attr_header+52], byteorder="little", signed=True)
        std_securityid = int.from_bytes(temp[attr_header+52:attr_header+56], byteorder="little", signed=True)
        std_updateseqnum = int.from_bytes(temp[attr_header+64:attr_header+72], byteorder="little", signed=True)
    
        return std_creatTime, std_modifiedTime, std_lastaccessTime, std_flags, std_vermax, std_vernum, std_classid, std_ownerid, std_securityid, std_updateseqnum
    else: return 0

def fna(temp):
    if int.from_bytes(temp[0:4], byteorder="little", signed=True) == 48:
        
        fna_parentEntryNum = int.from_bytes(temp[attr_header:attr_header+6], byteorder="little", signed=True)
        fna_parentSeqNum = int.from_bytes(temp[attr_header+6:attr_header+8], byteorder="little", signed=True)
        fna_creatTime = timestamp_change(temp[attr_header+8:attr_header+16])
        fna_modifiedTime = timestamp_change(temp[attr_header+(8*2):attr_header+(8*3)])
        fna_lastaccessTime = timestamp_change(temp[attr_header+(8*4):attr_header+(8*5)])
        fna_fileSize = int.from_bytes(temp[attr_header+(8*6):attr_header+(8*7)], byteorder="little", signed=True)
        fna_flags = flags(int.from_bytes(temp[attr_header+(8*7):attr_header+(8*7)+4], byteorder="little", signed=True))
        fna_fileNameLen = (int.from_bytes(temp[attr_header+(8*8):attr_header+(8*8)+1], byteorder="little", signed=True)*2)
        fna_fileNameSpace = name_type(int.from_bytes(temp[attr_header+(8*8)+1:attr_header+(8*8)+2], byteorder="little", signed=True))
        fna_filename = filename_change(temp[attr_header+(8*8)+2:attr_header+(8*8)+2+fna_fileNameLen])
        
    
        return fna_parentEntryNum, fna_parentSeqNum, fna_creatTime, fna_modifiedTime, fna_lastaccessTime, fna_fileSize, fna_flags, fna_fileNameSpace, fna_filename
    else: return 0

