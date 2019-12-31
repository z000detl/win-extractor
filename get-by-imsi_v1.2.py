"""
    Title: filter pfcp, ngap by imsi
    Version 1.0
    Creator: zhou tong
    Used for SHU project
    Date: 2019-12-25
    Usage： python get-by-imsi.py <pcap file> <imsi>
"""
import time
import sys
import subprocess
import re

################################  functions ######################################

def teid2str( teid ="" ):
	if( not len(teid) ):
		return teid
	teid = teid.lower().replace("0x","")
	return ':'.join([teid[i:min(i+2,len(teid))] for i in range(0,len(teid),2)])

def gtpv2tied_to_s1apteid( filter_string = "" ):
	if( not len(filter_string) ):
		return filter_string
	set_tmp = set()
	for x in re.findall(r"[0-9a-f]{8}",filter_string,re.I):
		set_tmp = set_tmp | { "s1ap.gTP_TEID=="+teid2str(x) }
	return "||".join( set_tmp )
	

def filter_pfcp(imsi,file_name):

	"""
	1. search imsi in pfcp
	"""
	filter_patten = '\"pfcp && e212.imsi == ' +imsi+ '\"'
	Tfield = ' -Tfields -e pfcp.seqno'
	cmd = '"C:\\Program Files\\wireshark\\tshark.exe\" -n -r \"' + file_name +'\" -2 -R ' +filter_patten + Tfield +' 2>null'
	print("\n",cmd,"\n")

	tmp_list = []
	for x in set(subprocess.getoutput( cmd ).split("\n")):
		if(len(x)>0):
			tmp_list.append( 'pfcp.seqno == ' + x )

	if(len(tmp_list)<=0):
		print("imsi %s not found in pfcp" %imsi);
		return ""

	"""
	2. search pfcp.seid by pfcp.seqno
	"""	
	filter_pfcp = "||".join(tmp_list)
	#print("filter_pfcp= ",filter_pfcp)

	filter_patten = '\"' + filter_pfcp + '\"'
	Tfield = ' -Tfields -e pfcp.seid'
	cmd = '"C:\\Program Files\\wireshark\\tshark.exe\" -n -r \"' + file_name +'\" -2 -R ' +filter_patten + Tfield +' 2>null'
	#print("\n",cmd,"\n")

	tmp_set = set(subprocess.getoutput( cmd ).replace('\n',',').split(","))
	tmp_set.discard('0x0000000000000000')
	tmp_set.discard('')
	
	set_pfcp_seid = set()
	for x in tmp_set:
		set_pfcp_seid = set_pfcp_seid |  { 'pfcp.seid==' + x }

	return "||".join( set_pfcp_seid )

def filter_pfcp_ngap(imsi,file_name):

	"""
	1. search imsi in pfcp
	"""
	filter_patten = '\"pfcp && e212.imsi == ' +imsi+ '\"'
	Tfield = ' -Tfields -e pfcp.seqno'
	cmd = '"C:\\Program Files\\wireshark\\tshark.exe\" -n -r \"' + file_name +'\" -2 -R ' +filter_patten + Tfield +' 2>null'
	print("\n",cmd,"\n")

	tmp_list = []
	for x in set(subprocess.getoutput( cmd ).split("\n")):
		if(len(x)>0):
			tmp_list.append( 'pfcp.seqno == ' + x )

	if(len(tmp_list)<=0):
		print("imsi %s not found in pfcp" %imsi);
		return ""

	"""
	2. search pfcp.teid used in ngap by pfcp.seqno
	"""	
	filter_pfcp = "||".join(tmp_list)
	#print("filter_pfcp= ",filter_pfcp)

	filter_patten = '\"' + filter_pfcp + '\"'
	Tfield = ' -Tfields -e pfcp.f_teid.teid'
	cmd = '"C:\\Program Files\\wireshark\\tshark.exe\" -n -r \"' + file_name +'\" -2 -R ' +filter_patten + Tfield +' 2>null'
	#print("\n",cmd,"\n")

	tmp_list = []
	for x in set(subprocess.getoutput( cmd ).split("\n")):
		if len(x) > 0:
			tmp_list.append( 'ngap.gTP_TEID == ' + teid2str(x) )

	"""
	3. search ngap id by teid
	"""	
	if( len(tmp_list)<1 ):
		print("no gtp teid found in pfcp.");
		return filter_pfcp
	
	print("Searching in ngap...");
	filter_ngap = '\"' + " || ".join(tmp_list) + '\"'
	#print(filter_ngap)

	filter_patten = filter_ngap
	Tfield = ' -Tfields -e ngap.RAN_UE_NGAP_ID -e ngap.AMF_UE_NGAP_ID'
	cmd = '"C:\\Program Files\\wireshark\\tshark.exe\" -n -r \"' + file_name +'\" -2 -R ' +filter_patten + Tfield +' 2>null'
	print("\n",cmd,"\n")

	set_ranid = set()
	set_amfid = set()
	tmp_set = set(subprocess.getoutput( cmd ).split('\n'))
	tmp_set.discard('')
	
	if(len(tmp_set)==0):
		return ""
	
	for x in tmp_set:
		y = x.split('\t')
		set_ranid = set_ranid | {y[0]}
		set_amfid = set_amfid | {y[1]}

	set_ranid.discard('')
	set_amfid.discard('')
	
	if( len(set_ranid)>0 ):
		tmp_set = set()
		for x in set_ranid:
			tmp_set = tmp_set | { 'ngap.RAN_UE_NGAP_ID=='+x }
		set_ranid = tmp_set

	if( len(set_amfid)>0 ):
		tmp_set = set()
		for x in set_amfid:
			tmp_set = tmp_set | { 'ngap.AMF_UE_NGAP_ID=='+x }
		set_amfid = tmp_set
	
	tmp_set = set_ranid | set_amfid
	tmp_set.discard('')
	return "||".join( tmp_set ) +"||"+filter_pfcp

	
def filterHTTP2(imsi, file_name):
	"""
		http2.header.value
		http2.streamid
	"""	
	filter_patten = '\"http2.header.value contains ' + imsi + '|| json.value.string contains ' + imsi + '\"'
	Tfield = ' -Tfields -e http2.streamid'
	cmd = '"C:\\Program Files\\wireshark\\tshark.exe\" -n -r \"' + file_name +'\" -2 -R ' +filter_patten + Tfield +' 2>null'
	print("\n===================================================================================");
	print("\n",cmd,"\n")

	tmp_list = []
	tmp_set = set( subprocess.getoutput( cmd ).replace('\n',',').split(',') )
	#print(tmp_set)
	tmp_set.discard('')
	#print(tmp_set)
	
	filter_http2 = ''
	if( len(tmp_set)>0 ):
		for x in tmp_set:
			tmp_list.append( "http2.streamid == " + x )
		filter_http2 = "||".join(tmp_list)
		#print(filter_http2)
	
	return filter_http2

def filterGTPV2(imsi, file_name):

	filter_patten = '\"gtpv2 && e212.imsi == ' +imsi+ '\"'
	Tfield = ' -Tfields -e gtpv2.f_teid_gre_key -e gtpv2.seq'
	cmd = '"C:\\Program Files\\wireshark\\tshark.exe\" -n -r \"' + file_name +'\" -2 -R ' +filter_patten + Tfield +' 2>null'
	print("\n===================================================================================");
	print("\n",cmd,"\n")

	set_seq  = set()
	set_teid = set()
	
	tmp_set = set(subprocess.getoutput( cmd ).split('\n'))
	tmp_set.discard('')
	if( len(tmp_set)<1 ):
		return ""
	
	for x in tmp_set:
		y = x.split('\t')
		#print(y)
		set_seq  = set_seq | {y[1]}
		set_teid = set_teid|set(y[0].split(','))

	set_teid.discard('0x00000000')
	set_teid.discard('0xffffffff')
	set_teid.discard('')
	set_seq.discard('')
	
	if( len(set_teid)+len(set_seq) ==0 ):
		return ""
	#print(set_teid,'\n',set_seq)

	#using seqno to filter more gtpv2.teid
	filter_gtpv2 = ''
	tmp_list = []
	if( len(set_seq)>0 ):
		for x in set_seq:
			tmp_list.append( "gtpv2.seq == " + x )
		filter_gtpv2 = "||".join(tmp_list)	
		
	filter_patten = '\"' +filter_gtpv2+ '\"'
	Tfield = ' -Tfields -e gtpv2.f_teid_gre_key'
	cmd = '"C:\\Program Files\\wireshark\\tshark.exe\" -n -r \"' + file_name +'\" -2 -R ' +filter_patten + Tfield +' 2>null'
	print("\n===================================================================================");
	print("\n",cmd,"\n")

	set_teid = set_teid | set(subprocess.getoutput( cmd ).replace('\n',',').split(','))
	set_teid.discard('0x00000000')
	set_teid.discard('0xffffffff')
	set_teid.discard('')	
	
	tmp_list = []
	if( len(set_teid)>0 ):
		for x in set_teid:
			tmp_list.append( "gtpv2.teid == " + x )
		filter_gtpv2 = filter_gtpv2 +"||" + "||".join(tmp_list)

	#print(filter_gtpv2)
	return filter_gtpv2

def filterDIAMETER(imsi, file_name):
	filter_patten = '\"diameter && e212.imsi == ' +imsi+ '\"'
	Tfield = ' -Tfields -e diameter.hopbyhopid'
	cmd = '"C:\\Program Files\\wireshark\\tshark.exe\" -n -r \"' + file_name +'\" -2 -R ' +filter_patten + Tfield +' 2>null'
	print("\n===================================================================================");
	print("\n",cmd,"\n")

	tmp_set = set(subprocess.getoutput( cmd ).split('\n'))
	tmp_set.discard('')
	#print('\n',tmp_set,'\n')
	if( len(tmp_set)<1 ):
		return ""
	
	set_hopid  = set()
	for x in tmp_set:
		set_hopid = set_hopid | {"diameter.hopbyhopid=="+x}
	
	return "||".join(set_hopid)

def filterS1AP(imsi, file_name, infilter=""):

	if(len(imsi)+len(infilter) ==0):
		return ""

	set_enbid = set()
	set_mmeid = set()
		
	#filter by imsi
	if( len(imsi) == 15 ):
	
		filter_patten = '\"s1ap && e212.imsi == ' +imsi+ '\"'
		Tfield = ' -Tfields -e s1ap.ENB_UE_S1AP_ID -e s1ap.MME_UE_S1AP_ID'
		cmd = '"C:\\Program Files\\wireshark\\tshark.exe\" -n -r \"' + file_name +'\" -2 -R ' +filter_patten + Tfield +' 2>null'
		print("\n===================================================================================");
		print("\n",cmd,"\n")

		tmp_set = set(subprocess.getoutput( cmd ).split('\n'))
		tmp_set.discard('')
		#print('\n',tmp_set,'\n')
		if( len(tmp_set)<1 ):
			return ""
		
		for x in tmp_set:
			y = x.split('\t')
			set_enbid = set_enbid | {y[0]}
			set_mmeid = set_mmeid | {y[1]}
	
	set_enbid.discard('')
	set_mmeid.discard('')
	
	if( len(set_enbid)>0 ):
		tmp_set = set()
		for x in set_enbid:
			tmp_set = tmp_set | { 's1ap.ENB_UE_S1AP_ID=='+x }
		set_enbid = tmp_set

	if( len(set_mmeid)>0 ):
		tmp_set = set()
		for x in set_mmeid:
			tmp_set = tmp_set | { 's1ap.MME_UE_S1AP_ID=='+x }
		set_mmeid = tmp_set
	
	
	set_infilter = set(infilter.split('||'))

	tmp_set = set_enbid | set_mmeid | set_infilter
	tmp_set.discard('')
	
	#now begin 2nd filter by enbid or mmeid
	if( len(tmp_set) >0 ):
	
		filter_patten = '\"'+ "||".join(tmp_set) +'\"'
		Tfield = ' -Tfields -e s1ap.ENB_UE_S1AP_ID -e s1ap.MME_UE_S1AP_ID'
		cmd = '"C:\\Program Files\\wireshark\\tshark.exe\" -n -r \"' + file_name +'\" -2 -R ' +filter_patten + Tfield +' 2>null'
		print("\n===================================================================================");
		print("\n",cmd,"\n")

		tmp_set = set(subprocess.getoutput( cmd ).split('\n'))
		tmp_set.discard('')
		#print('\n',tmp_set,'\n')
		if( len(tmp_set)<1 ):
			return ""
		
		set_enbid = set()
		set_mmeid = set()
		
		for x in tmp_set:
			y = x.split('\t')
			set_enbid = set_enbid | {y[0]}
			set_mmeid = set_mmeid | {y[1]}
	
		set_enbid.discard('')
		set_mmeid.discard('')
		
		if( len(set_enbid)>0 ):
			tmp_set = set()
			for x in set_enbid:
				tmp_set = tmp_set | { 's1ap.ENB_UE_S1AP_ID=='+x }
			set_enbid = tmp_set

		if( len(set_mmeid)>0 ):
			tmp_set = set()
			for x in set_mmeid:
				tmp_set = tmp_set | { 's1ap.MME_UE_S1AP_ID=='+x }
			set_mmeid = tmp_set
		
		tmp_set = set_enbid | set_mmeid | set_infilter
		tmp_set.discard('')	
		return "||".join(tmp_set)
		
	else:
		return ""

################################  main here ######################################

#file_name = r"c:\RSO\2014-3-SHU\project\_2019\5G_SA\signaling\huawei_1223_vonr_v7_ims_reg_filter.pcapng"
#imsi = r"460091402000017"

while(1):
	imsi = ""
	file_name = ""
	imsi = input("\nInput imsi for search:")
	if(len(imsi)<=0):
		exit()
	file_name = input("draw a wireshark file into this windows: \n")
	
	#filter s1ap by imsi
	filter_s1ap = filterS1AP(imsi,file_name,"")
	if(len(filter_s1ap)>0):
		filter_s1ap = filterS1AP("",file_name,filter_s1ap)
	
	#filter gtpv2 by imsi 
	#get user plane gtp teid which will be used for s1ap filter
	filter_gtpv2 = filterGTPV2(imsi,file_name)
	filter_s1ap_byteid = filterS1AP("",file_name,gtpv2tied_to_s1apteid(filter_gtpv2))
		
	set_filter_all = { filter_pfcp(imsi,file_name),
					   filter_pfcp_ngap(imsi,file_name),
	                   filterHTTP2(imsi,file_name), 
					   filter_gtpv2,
					   filterDIAMETER(imsi,file_name),
					   filter_s1ap,
					   filter_s1ap_byteid
					 }
	tmp_set = set()
	for x in set_filter_all:
		tmp_set = tmp_set | set(x.split("||"))
	tmp_set.discard('')
	filter_all = "||".join(tmp_set)

	"""
		filter all
	"""	
	print("\n===================================================================================");
	print("Final filter for imsi %s is : \n" % imsi, filter_all)

	filter_patten = '\"' + filter_all + '\"'
	tmp_list = file_name.split("\\")
	tmp_list[-1] = "filtered-"+tmp_list[-1]
	outfile = "\\".join(tmp_list)
	
	if( len(filter_all) < 1 ):
		print(" Null filter, skip");
		continue
	cmd = '"C:\\Program Files\\wireshark\\tshark.exe\" -n -r \"' + file_name +'\" -2 -R ' + filter_patten + ' -w \"'+outfile+'\"'
	print("\n===================================================================================");
	print("filtered file is \" "+outfile+" \"by command:\n")
	print(cmd)
	subprocess.run(cmd)
	
