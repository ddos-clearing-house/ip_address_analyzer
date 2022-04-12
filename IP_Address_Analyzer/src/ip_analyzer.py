#!/usr/bin/python3
# -*- coding: utf-8 -*-

###############################################################################
# CONCORDIA Project
#  
# This project has received funding from the European Union’s Horizon
# 2020 Research and Innovation program under Grant Agreement No 830927.
#  
# Ramin Yazdani - r.yazdani@utwente.nl
###############################################################################

###############################################################################

from __future__ import unicode_literals
import os
import sys
import json
import time
import ipaddress
import IP2Location
import IP2Proxy
import pyasn
import requests
import censys.ipv4
import shodan
import argparse
import pandas as pd
import zipfile
import tarfile
import re
import subprocess
import ast
from requests.exceptions import HTTPError
from bs4 import BeautifulSoup
from urllib.request import Request, urlopen
from subprocess import *
from datetime import datetime, date
from dotenv import load_dotenv
#from google.cloud import bigquery



def bgp_update():


    if not os.path.exists('data/bgp_data/ipasn_'+today+'.dat'):
        try:
            os.system("rm data/bgp_data/*")
        except:
            pass
        os.system("pyasn_util_download.py --latest")
        os.system("mv rib.* data/bgp_data/")
        os.system("pyasn_util_convert.py --single data/bgp_data/rib.* data/bgp_data/ipasn_"+today+".dat")
        os.system("rm data/bgp_data/rib.*")



def ip_type(ip):

    return ip,\
           ipaddress.ip_address(ip).is_global,\
           ipaddress.ip_address(ip).is_private,\
           ipaddress.ip_address(ip).is_loopback,\
           ipaddress.ip_address(ip).is_link_local,\
           ipaddress.ip_address(ip).is_multicast,\
           ipaddress.ip_address(ip).is_reserved,\
           ipaddress.ip_address(ip).is_unspecified\



def asn_lookup(ip):

    asndb = pyasn.pyasn('data/bgp_data/ipasn_'+today+'.dat')
    return ip, str(asndb.lookup(ip)[0])



def MLab(asn):

    '''
    try:
        os.system("bq query --use_legacy_sql=false --format csv --max_rows=100000000 'SELECT result.C2S.ClientIP,result.C2S.MeanThroughputMbps,result.C2S.StartTime FROM `measurement-lab.ndt.ndt5` WHERE result.C2S.MeanThroughputMbps!=0 and result.C2S.ClientIP like \"" + str(ip) + "\" ' > " + str(ip) + ".csv")
        df = pd.read_csv (str(ip) + '.csv', low_memory=False)
        return "{0:.2f}".format(df.MeanThroughputMbps.mean()), "/32"

    except:
        return "-"

    
        prefix = "/24"
        try:
            df = pd.read_csv (str(ip) + '.csv', low_memory=False)
        except:
            os.system("bq query --use_legacy_sql=false --format csv --max_rows=100000000 'SELECT result.C2S.ClientIP,result.C2S.MeanThroughputMbps,result.C2S.StartTime FROM `measurement-lab.ndt.ndt5` WHERE result.C2S.MeanThroughputMbps!=0 and result.C2S.ClientIP like \"" + str(ip).rsplit(".", 1)[0]+".%" + "\" ' > " + str(ip) + ".csv")

        try:
            df = pd.read_csv (str(ip) + '.csv', low_memory=False)
            return "{0:.2f}".format(df.MeanThroughputMbps.mean()), "/24"
        except:
            return "-"

    os.system("rm "+ str(ip) + ".csv")
    '''

    today = datetime.today()
    year = today.year


    ul = "None"
    dl = "None"
    
    try:
        url = 'https://statistics.measurementlab.net/v0/asn/'+asn+'/'+str(year)+'/histogram_daily_stats.json'
        response = urlopen(url)
        string = response.read().decode('utf-8')
        json_obj = json.loads(string)

        upload_AVG = []
        download_AVG = []


        for i in json_obj:
            upload_AVG.append(i['upload_AVG'])
            download_AVG.append(i['download_AVG'])
        ul = round(np.mean(upload_AVG),1)
        dl = round(np.mean(download_AVG),1)

    except:
        pass

    return asn, ul, dl



def ipinfo(ip):

    time.sleep(0.2)
    url='https://ipinfo.io/'+ip
    req = Request(url,headers={'User-Agent': 'Mozilla/5.0'})
    page = urlopen(req).read()
    bs = BeautifulSoup(page, "lxml")

    found = 0
    list = []
    list.append(ip)
    for tr in bs.findAll('tr'):
        if "Anycast" in str(tr):
            if "True" in str(tr):
                list.append("True")
                found = 1
            elif "False" in str(tr):
                list.append("False")
                found = 1
            break;

    if found == 0:
        return ip, "-"
    else:
        return list




def censys_query(ip):

    #os.system("censys config")
    
    censys_id = os.getenv('CENSYS_ID')
    censys_secret = os.getenv('CENSYS_SECRET')

    c = censys.ipv4.CensysIPv4(censys_id, censys_secret)

    fields = [
        "ip",
        "protocols",
    ]

    list = []

    for page in c.search(
            "ip: "+str(ip),
            fields,
            max_records=10,
        ):
        list.extend(pd.DataFrame(page, index=None).protocols)
    return ip, list



def shodan_query(ip):

    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
    api = shodan.Shodan(SHODAN_API_KEY)

    try:
        ipinfo = api.host(ip)
        return ip, ipinfo['os'], ipinfo['ports']
    except:
        return ip, "-", "-"



def ip2location_ip2proxy_lite_bin_lookup(ip):

    token = os.getenv("IP2LOCATION_LITE_DOWNLOAD_KEY")

    if not os.path.exists('data/ip2location/lite/DB11.zip'):
        url_db11 = 'https://www.ip2location.com/download/?token='+token+'&file=DB11LITEBIN'
        r = requests.get(url_db11, allow_redirects=True)
        open('data/ip2location/lite/DB11.zip', 'wb').write(r.content)
        with zipfile.ZipFile('data/ip2location/lite/DB11.zip', 'r') as db11:
            db11.extractall('data/ip2location/lite/')    

    if not os.path.exists('data/ip2proxy/lite/PX10.zip'):
        url_px10 = 'https://www.ip2location.com/download/?token='+token+'&file=PX10LITEBIN'
        r = requests.get(url_px10, allow_redirects=True)
        open('data/ip2proxy/lite/PX10.zip', 'wb').write(r.content)
        with zipfile.ZipFile('data/ip2proxy/lite/PX10.zip', 'r') as px10:
            px10.extractall('data/ip2proxy/lite/') 

    list =[]
    list.append(ip)


    ip2l_lite_db = IP2Location.IP2Location(os.path.join("data/ip2location/lite", "IP2LOCATION-LITE-DB11.BIN"))

    record = ip2l_lite_db.get_all(ip)

    list.append (record.country_short)
    list.append (record.country_long)
    #list.append (record.region)
    #list.append (record.city)
    list.append (record.isp)	
    list.append (record.latitude)
    list.append (record.longitude)			
    #list.append (record.domain)
    #list.append (record.zipcode)
    #list.append (record.timezone)
    list.append (record.netspeed)
    #list.append (record.idd_code)
    #list.append (record.area_code)
    #list.append (record.weather_code)
    #list.append (record.weather_name)
    #list.append (record.mcc)
    #list.append (record.mnc)
    #list.append (record.mobile_brand)
    #list.append (record.elevation)
    #list.append (record.usage_type)



    ip2p_lite_db = IP2Proxy.IP2Proxy()


    # open IP2Proxy BIN database for proxy lookup
    ip2p_lite_db.open(os.path.join("data/ip2proxy/lite", "IP2PROXY-LITE-PX10.BIN"))

    record = ip2p_lite_db.get_all(ip)
    
    #list.append (str(record['is_proxy']))
    #list.append (record['proxy_type'])
    #list.append (record['country_short'])
    #list.append (record['country_long'])
    #list.append (record['region'])
    #list.append (record['city'])
    #list.append (record['isp'])
    #list.append (record['domain'])
    list.append (record['usage_type'])
    #list.append (record['asn'])
    #list.append (record['as_name'])
    #list.append (record['last_seen'])
    #list.append (record['threat'])

    # close IP2Proxy BIN database
    ip2p_lite_db.close()

    return list



def ip2location_ip2proxy_bin_lookup(ip):

    flag = 0
    list =[]
    list.append(ip)
 
    for file in os.listdir("data/ip2location"):
        if file.endswith(".BIN"):
            ip2l_database_name = file
            break
    
    ip2l_db = IP2Location.IP2Location(os.path.join("data/ip2location", ip2l_database_name))
    record = ip2l_db.get_all(ip)

    all_fields = ['country_short', 'country_long', 'region', 'city', 'isp', 'latitude', 'longitude', 'domain', 'zipcode', 'timezone', 'netspeed', 'idd_code', 'area_code', 'weather_code', 'weather_name', 'mcc', 'mnc', 'mobile_brand', 'elevation', 'usage_type']
    desired_fields = ['country_short', 'country_long', 'isp', 'latitude', 'longitude', 'netspeed', 'usage_type']

    for field in desired_fields:
        try:
            list.append (getattr(record, field))
            if r == 'usage_type':
                flag = 1
        except:
            list.append ("-")

    ip2l_db.close()


    for file in os.listdir("data/ip2proxy"):
        if file.endswith(".BIN"):
            ip2p_database_name = file
            break

    ip2p_db = IP2Proxy.IP2Proxy(os.path.join("data/ip2proxy", ip2p_database_name))
    record = ip2p_db.get_all(ip)

    all_fields = ['is_proxy', 'proxy_type', 'country_short', 'country_long', 'region', 'city', 'isp', 'domain', 'usage_type', 'asn', 'as_name', 'last_seen', 'threat']
    desired_fields = ['usage_type']

    for field in desired_fields:
        try:
            if field == 'usage_type' and flag == 1:
                pass
            else:
                list.append (record[field])
        except:
            list.append ("-")

    ip2p_db.close()

    return list
    
    

def read_geo_csv(filename):

    tar = tarfile.open(filename, "r:gz")
    untarred=[members for members in tar if members.name.startswith("./DB")]
    db16=tar.extractfile(untarred[0])
    db23=tar.extractfile(untarred[1])

    zf16 = zipfile.ZipFile(db16)
    zf23 = zipfile.ZipFile(db23)

    ipgeo16 = pd.read_csv(zf16.open('IPV6-COUNTRY-REGION-CITY-LATITUDE-LONGITUDE-ZIPCODE-TIMEZONE-ISP-DOMAIN-NETSPEED-AREACODE.CSV'), header=None, encoding = 'utf8',dtype={'ip_from':'str', 'ip_to':'str'}, low_memory=False)
    ipgeo16 = ipgeo16.rename(columns={0: "ip_from", 1: "ip_to", 2: "cc", 3: "c_name", 4:"region", 5:"city" , 6:"latitude", 7:"longitude",8:"zipcode", 9:"timezone", 10:"isp", 11:"domain_name", 12: "net_speed", 13: "idd_code", 14: "area_code"})

    ipgeo23 = pd.read_csv(zf23.open('IPV6-COUNTRY-REGION-CITY-LATITUDE-LONGITUDE-ISP-DOMAIN-MOBILE-USAGETYPE.CSV'), header=None, encoding = 'utf8',dtype={'ip_from':'str', 'ip_to':'str'}, low_memory=False)
    ipgeo23 = ipgeo23.rename(columns={0: "ip_from", 1: "ip_to", 2: "cc", 3: "c_name", 4:"region", 5:"city" , 6:"latitude", 7:"longitude",8:"isp", 9:"domain_name", 10:"mcc", 11:"mnc", 12: "mobile_brand", 13: "usage_type"})

    return ipgeo16, ipgeo23



def range2prefix(ipgeo16, ipgeo23):

    ipgeo16['ip_from']=pd.to_numeric(ipgeo16.ip_from,errors='coerce')
    ipgeo16['ip_to']=pd.to_numeric(ipgeo16.ip_to,errors='coerce')
    ipgeo16=ipgeo16[(ipgeo16.ip_from>=281470681743360) & (ipgeo16.ip_to<=281474976710656)].copy()
    ipgeo16["prefix"]=[[ipaddr for ipaddr in ipaddress.summarize_address_range(ipaddress.IPv6Address(int(sip)).ipv4_mapped, ipaddress.IPv6Address(int(eip)).ipv4_mapped)]\
                for sip, eip, in zip(ipgeo16.ip_from, ipgeo16.ip_to)]

    ipgeoexp16=ipgeo16.explode('prefix')
    #ipgeoexp['ip_from']=ipgeoexp.prefix.apply(lambda x: int(x.network_address))
    #ipgeoexp['ip_to']=ipgeoexp.prefix.apply(lambda x: int(x.broadcast_address))
    ipgeoexp16['prefix']=ipgeoexp16['prefix'].astype(str)


    ipgeo23['ip_from']=pd.to_numeric(ipgeo23.ip_from,errors='coerce')
    ipgeo23['ip_to']=pd.to_numeric(ipgeo23.ip_to,errors='coerce')
    ipgeo23=ipgeo23[(ipgeo23.ip_from>=281470681743360) & (ipgeo23.ip_to<=281474976710656)].copy()
    ipgeo23["prefix"]=[[ipaddr for ipaddr in ipaddress.summarize_address_range(ipaddress.IPv6Address(int(sip)).ipv4_mapped, ipaddress.IPv6Address(int(eip)).ipv4_mapped)]\
                for sip, eip, in zip(ipgeo23.ip_from, ipgeo23.ip_to)]
    ipgeoexp23=ipgeo23.explode('prefix')
    #ipgeoexp['ip_from']=ipgeoexp.prefix.apply(lambda x: int(x.network_address))
    #ipgeoexp['ip_to']=ipgeoexp.prefix.apply(lambda x: int(x.broadcast_address))
    ipgeoexp23['prefix']=ipgeoexp23['prefix'].astype(str)
    ipgeoexp23['mcc']=ipgeoexp23['mcc'].astype(str)
    ipgeoexp23['mnc']=ipgeoexp23['mnc'].astype(str)

    return ipgeoexp16, ipgeoexp23



def range2prefix6(ipgeo16, ipgeo23):

    ipgeo16["prefix"]=[[ipaddr for ipaddr in ipaddress.summarize_address_range(ipaddress.IPv6Address(int(sip)), ipaddress.IPv6Address(int(eip)))]\
                    for sip, eip, in zip(ipgeo16.ip_from, ipgeo16.ip_to)]
    ipgeoexp16=ipgeo16.explode('prefix')
    ipgeoexp16['ip_from']=ipgeoexp16.prefix.apply(lambda x: int(x.network_address))
    ipgeoexp16['ip_to']=ipgeoexp16.prefix.apply(lambda x: int(x.broadcast_address))
    ipgeoexp16['prefix']=ipgeoexp16['prefix'].astype(str)


    ipgeo23["prefix"]=[[ipaddr for ipaddr in ipaddress.summarize_address_range(ipaddress.IPv6Address(int(sip)), ipaddress.IPv6Address(int(eip)))]\
                    for sip, eip, in zip(ipgeo23.ip_from, ipgeo23.ip_to)]
    ipgeoexp23=ipgeo23.explode('prefix')
    ipgeoexp23['ip_from']=ipgeoexp23.prefix.apply(lambda x: int(x.network_address))
    ipgeoexp23['ip_to']=ipgeoexp23.prefix.apply(lambda x: int(x.broadcast_address))
    ipgeoexp23['prefix']=ipgeoexp23['prefix'].astype(str)
    ipgeoexp23['mcc']=ipgeoexp23['mcc'].astype(str)
    ipgeoexp23['mnc']=ipgeoexp23['mnc'].astype(str)

    return ipgeoexp16, ipgeoexp23



def store_geo(ipgeoexp16, ipgeoexp23, date):

    ipgeoexp16.to_parquet('../data/ip2location/parquet/DB16_'+date+'.parquet', compression='gzip')
    ipgeoexp23.to_parquet('../data/ip2location/parquet/DB23_'+date+'.parquet', compression='gzip')



def ip2location_csv_lookup(ip_addresses):

    geodb_list = sorted(os.listdir('../data/ip2location/tar/'))
    date = re.search("([0-9]{4}\-[0-9]{2}\-[0-9]{2})", geodb_list[-1])[0]
    if not (os.path.exists('../data/ip2location/parquet/DB16_'+date+'.parquet') and os.path.exists('../data/ip2location/parquet/DB23_'+date+'.parquet')):
        ipgeo16,ipgeo23 = read_geo_csv('../data/ip2location/tar/'+geodb_list[-1])
        ipgeoexp16, ipgeoexp23 = range2prefix(ipgeo16, ipgeo23)
        store_geo(ipgeoexp16, ipgeoexp23, date)

    geo16 = pd.read_parquet('../data/ip2location/parquet/DB16_'+date+'.parquet')
    geo16=geo16.drop_duplicates(subset=["ip_from","ip_to","cc","latitude","longitude"])
    idx = pd.IntervalIndex.from_arrays(geo16['ip_from'], geo16['ip_to'], closed='both')
    geo16.index=idx

    geo23 = pd.read_parquet('../data/ip2location/parquet/DB23_'+date+'.parquet')
    geo23=geo23.drop_duplicates(subset=["ip_from","ip_to","cc","latitude","longitude"])
    idx = pd.IntervalIndex.from_arrays(geo23['ip_from'], geo23['ip_to'], closed='both')
    geo23.index=idx

    ip_addresses.columns = ["Source"]
    ip_addresses["ip_decimal"]=ip_addresses["Source"].apply(lambda x:int(ipaddress.ip_address(x)))
    ip_addresses["cc"]=geo23.loc[ip_addresses.ip_decimal+281470681743360,"cc"].values
    ip_addresses["c_name"]=geo23.loc[ip_addresses.ip_decimal+281470681743360,"c_name"].values
    ip_addresses["latitude"]=geo23.loc[ip_addresses.ip_decimal+281470681743360,"latitude"].values
    ip_addresses["longitude"]=geo23.loc[ip_addresses.ip_decimal+281470681743360,"longitude"].values
    ip_addresses["isp"]=geo23.loc[ip_addresses.ip_decimal+281470681743360,"isp"].values
    ip_addresses["usage_type"]=geo23.loc[ip_addresses.ip_decimal+281470681743360,"usage_type"].values
    ip_addresses["net_speed"]=geo16.loc[ip_addresses.ip_decimal+281470681743360,"net_speed"].values

    return ip_addresses.drop(['ip_decimal'], axis=1)



def fingerprint_extender(ip, category):

    fingerprint_json[category][ip]={}
    fingerprint_json[category][ip].update({'is_global':str(df_ipaddress[df_ipaddress.Source==ip]['is_global'].iloc[0])})
    fingerprint_json[category][ip].update({'is_private':str(df_ipaddress[df_ipaddress.Source==ip]['is_private'].iloc[0])})
    fingerprint_json[category][ip].update({'is_loopback':str(df_ipaddress[df_ipaddress.Source==ip]['is_loopback'].iloc[0])})
    fingerprint_json[category][ip].update({'is_link_local':str(df_ipaddress[df_ipaddress.Source==ip]['is_link_local'].iloc[0])})
    fingerprint_json[category][ip].update({'is_multicast':str(df_ipaddress[df_ipaddress.Source==ip]['is_multicast'].iloc[0])})
    fingerprint_json[category][ip].update({'is_reserved':str(df_ipaddress[df_ipaddress.Source==ip]['is_reserved'].iloc[0])})

    if 'asn' in lookup_list:
        if len(df_asn.loc[df_asn['Source']==ip,'ASN']):
            fingerprint_json[category][ip].update({'ASN':str(df_asn[df_asn.Source==ip]['ASN'].iloc[0])})

    if 'ip_lite' in lookup_list:
        if len(df_ip_lite.loc[df_ip_lite['Source']==ip,'cc']):
            fingerprint_json[category][ip].update({'Country_Code':str(df_ip_lite[df_ip_lite.Source==ip]['cc'].iloc[0])})
            fingerprint_json[category][ip].update({'Country_Name':str(df_ip_lite[df_ip_lite.Source==ip]['c_name'].iloc[0])})
            fingerprint_json[category][ip].update({'Latitude':str(df_ip_lite[df_ip_lite.Source==ip]['latitude'].iloc[0])})
            fingerprint_json[category][ip].update({'Longitude':str(df_ip_lite[df_ip_lite.Source==ip]['longitude'].iloc[0])})
            fingerprint_json[category][ip].update({'ISP':str(df_ip_lite[df_ip_lite.Source==ip]['isp'].iloc[0])})
            fingerprint_json[category][ip].update({'Usage_Type':str(df_ip_lite[df_ip_lite.Source==ip]['usage_type'].iloc[0])})
            fingerprint_json[category][ip].update({'Net_Speed':str(df_ip_lite[df_ip_lite.Source==ip]['net_speed'].iloc[0])})

    if 'ip2location' in lookup_list:
        if len(df_ip2location.loc[df_ip2location['Source']==ip,'cc']):
            fingerprint_json[category][ip].update({'Country_Code':str(df_ip2location[df_ip2location.Source==ip]['cc'].iloc[0])})
            fingerprint_json[category][ip].update({'Country_Name':str(df_ip2location[df_ip2location.Source==ip]['c_name'].iloc[0])})
            fingerprint_json[category][ip].update({'Latitude':str(df_ip2location[df_ip2location.Source==ip]['latitude'].iloc[0])})
            fingerprint_json[category][ip].update({'Longitude':str(df_ip2location[df_ip2location.Source==ip]['longitude'].iloc[0])})
            fingerprint_json[category][ip].update({'ISP':str(df_ip2location[df_ip2location.Source==ip]['isp'].iloc[0])})
            fingerprint_json[category][ip].update({'Usage_Type':str(df_ip2location[df_ip2location.Source==ip]['usage_type'].iloc[0])})
            fingerprint_json[category][ip].update({'Net_Speed':str(df_ip2location[df_ip2location.Source==ip]['net_speed'].iloc[0])})

    if 'ipinfo' in lookup_list:
        if len(df_ipinfo.loc[df_ipinfo['Source']==ip,'Anycast']):
            fingerprint_json[category][ip].update({'Anycast':str(df_ipinfo[df_ipinfo.Source==ip]['Anycast'].iloc[0])})

    if 'censys' in lookup_list:
        if len(df_censys.loc[df_censys['Source']==ip,'Open_ports']):
            fingerprint_json[category][ip].update({'Open_Ports_Censys':str(df_censys[df_censys.Source==ip]['Open_ports'].iloc[0])})

    if 'shodan' in lookup_list:
        if len(df_shodan.loc[df_shodan['Source']==ip,'Open_ports']):
            fingerprint_json[category][ip].update({'OS_Shodan':str(df_shodan[df_shodan.Source==ip]['OS'].iloc[0])})
            fingerprint_json[category][ip].update({'Open_Ports_Shodan':str(df_shodan[df_shodan.Source==ip]['Open_ports'].iloc[0])})

    if 'map' in lookup_list:
        fingerprint_json.update({'ip_map_url': map_plot})
            
    if 'mlab' in lookup_list:
        if len(df_mlab.loc[df_mlab['Source']==ip,'AS_Average_Upload_Mbps']):
            fingerprint_json[category][ip].update({'AS_Average_Upload_Mbps':str(df_mlab[df_mlab.Source==ip]['AS_Average_Upload_Mbps'].iloc[0])})
            fingerprint_json[category][ip].update({'AS_Average_Download_Mbps':str(df_mlab[df_mlab.Source==ip]['AS_Average_Download_Mbps'].iloc[0])})



def api_key_manager():

    os.system ("touch .env")
    with open('.env') as apikey_file:
        if 'ip_lite' in lookup_list:
            if not 'IP2LOCATION_LITE_DOWNLOAD_KEY' in apikey_file.read():
                with open('.env', 'a+') as f:
                    key= input("DOWNLOAD_KEY for IP2Location Lite database is not configured yet. Enter your key here:")
                    f.write('IP2LOCATION_LITE_DOWNLOAD_KEY='+key+'\n')
                f.close()

        apikey_file.seek(0)
        if 'censys' in lookup_list:
            if not 'CENSYS_ID' in apikey_file.read():
                with open('.env', 'a+') as f:
                    key= input("API ID for Censys database is not configured yet. Enter your ID here:")
                    f.write('CENSYS_ID='+key+'\n')
                f.close()

            apikey_file.seek(0)
            if not 'CENSYS_SECRET' in apikey_file.read():
                with open('.env', 'a+') as f:
                    key= input("API SECRET for Censys database is not configured yet. Enter your key here:")
                    f.write('CENSYS_SECRET='+key+'\n')
                f.close()

        apikey_file.seek(0)
        if 'shodan' in lookup_list:
            if not 'SHODAN_API_KEY' in apikey_file.read():
                with open('.env', 'a+') as f:
                    key= input("API_KEY for Shodan database is not configured yet. Enter your key here:")
                    f.write('SHODAN_API_KEY='+key+'\n')
                f.close()



def logo():

   print ('''
  _____  _____                  _   _            _   __     __ ______ ______  _____ 
 |_   _||  __ \          /\    | \ | |    /\    | |  \ \   / /|___  /| _____||  __ \ 
   | |  | |__) | ____   /  \   |  \| |   /  \   | |   \ \_/ /    / / | |__   | |__) | 
   | |  |  ___/ |____| / /\ \  | . ' |  / /\ \  | |    \   /    / /  |  __|  |  _  / 
  _| |_ | |           / ____ \ | |\  | / ____ \ | |____ | |    / /__ | |____ | | \ \ 
 |_____||_|          /_/    \_\|_| \_|/_/    \_\|______||_|   /_____||______||_|  \_\ 

          ''')


def dir_cleanup():

     now = time.time()

     if os.path.exists('data/ip2location/IP-COUNTRY-SAMPLE.BIN'):
         os.system("rm data/ip2location/IP-COUNTRY-SAMPLE.BIN")

     if len(os.listdir('data/ip2location/lite/')):
         for f in os.listdir('data/ip2location/lite/'):
             if os.stat('data/ip2location/lite/'+f).st_mtime<now-86400:
                 os.system("rm data/ip2location/lite/"+f)

     if os.path.exists('data/ip2location/IP2PROXY-IP-COUNTRY.BIN'):
         os.system("rm data/ip2location/IP2PROXY-IP-COUNTRY.BIN")

     if len(os.listdir('data/ip2proxy/lite/')):
         for f in os.listdir('data/ip2proxy/lite/'):
             if os.stat('data/ip2proxy/lite/'+f).st_mtime<now-86400:
                 os.system("rm data/ip2proxy/lite/"+f)


def map_plot():

    global_ips.to_csv('ip_list.csv', header=False, index=False)
    #x=os.popen("cat ip_list.csv | curl -XPOST --data-binary @- \"ipinfo.io/map?cli=1\"").read()
    #print(x)

    output = Popen(["cat ip_list.csv | curl -XPOST --data-binary @- \"ipinfo.io/map?cli=1\""], stdout=PIPE, stderr=PIPE, shell=True).communicate()[0]
    map_url = ast.literal_eval(output.decode('utf-8'))["reportUrl"]
    print ("map URL: ", map_url)
    os.system("rm ip_list.csv")
    return ast.literal_eval(output.decode('utf-8'))["reportUrl"]


if __name__ == '__main__':


    parser = argparse.ArgumentParser(description='')
    parser.add_argument('--input', metavar='input_fingerprint', required=True, help='Input fingurprint file name')
    args = parser.parse_args()

    try:
        args = parser.parse_args()
    except:
        parser.print_help()
        sys.exit(0)

    input_file = args.input
    path, file = os.path.split(input_file)


    df_lookup = pd.DataFrame ({'lookup_number': [1,2,3,4,5,6,7,8,9], 'lookup_name': ['ipaddress', 'asn', 'ip_lite', 'ip2location', 'ipinfo', 'censys', 'shodan', 'map', 'mlab']})

    os.system("clear")
    logo()
    print ("This script adds info about IP addresses existing in a fingerprint by looking up multiple sources.\n")
    print ("List of available tests to run:\n")
    print ("    1) IP address type (always runs)")
    print ("    2) AS numbers lookup using BGP information of RouteViews")
    print ("    3) Geo-ip database lookup on IP2Location and IP2Proxy Lite (free)")
    print ("    4) Geo-ip database lookup on IP2Location (licenced)")
    print ("    5) Anycast usage lookup on ipinfo")
    print ("    6) Open ports lookup on Censys")
    print ("    7) Operating system and open ports lookup on Shodan")
    print ("    8) Plot a world map of IP address geolocations")
    print ("    9) Network speed measurements of M-LAB\n")

    input_list = list(map(int, input("Enter the list of desired queries to run separated by space (numbers only): \n").split()))
    lookup_list = list(df_lookup[df_lookup['lookup_number'].isin(input_list)]['lookup_name'])

    today=date.today().strftime("%Y%m%d")

    dir_cleanup()
    api_key_manager()
    load_dotenv()

    # List IP addresses exisiting in the fingerprint file:
    ip_list = []
    attackers = []
    amplifiers = []
    with open(input_file) as fingerprint:
        fingerprint_json = json.load(fingerprint)

    pattern = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    for ipv4 in fingerprint_json['attackers']:
        if pattern.match(ipv4):
            ip_list.append(ipv4)
            attackers.append(ipv4)

    for ipv4 in fingerprint_json['amplifiers']:
        if pattern.match(ipv4):
            ip_list.append(ipv4)
            amplifiers.append(ipv4)

    df_iplist = pd.DataFrame(ip_list)
    df_iplist.columns=['Source']


    # Check IP types and filter public IP addresses for further investigations:
    print("Running IP-type analysis ...")
    iptype_results=[]
    iptype_results.extend(df_iplist.Source.apply(ip_type))
    df_ipaddress = pd.DataFrame(iptype_results,columns=["Source","is_global", "is_private", "is_loopback", "is_link_local", "is_multicast", "is_reserved", "is_unspecified"])

    global_ips = df_ipaddress[(df_ipaddress.is_global==True) & (df_ipaddress.is_multicast==False)].reset_index(drop=True)
    global_ips = global_ips[['Source']]



    if 'asn' in lookup_list:
        print ("Running ASN lookups using RouteViews BGP data ...")
        bgp_update()
        asn_results = []
        asn_results.extend(global_ips.Source.apply(asn_lookup))
        df_asn = pd.DataFrame(asn_results, columns=["Source", "ASN"])

    if 'ip_lite' in lookup_list:
        print ("Running geo-ip queries using IP2Location and IP2Proxy Lite ...")
        ip2l_ip2p_lite_results= []
        ip2l_ip2p_lite_results.extend(global_ips.Source.apply(ip2location_ip2proxy_lite_bin_lookup))
        df_ip_lite = pd.DataFrame(ip2l_ip2p_lite_results, columns=["Source", "cc", "c_name", "isp", "latitude", "longitude", "net_speed", "usage_type"])

    if 'ip2location' in lookup_list:
        print ("Running geo-ip queries using IP2Location and/or IP2Proxy ...")
        ip2l_ip2p_results= []
        ip2l_ip2p_results.extend(global_ips.Source.apply(ip2location_ip2proxy_bin_lookup))
        df_ip2location = pd.DataFrame(ip2l_ip2p_results, columns=["Source", "cc", "c_name", "isp", "latitude", "longitude", "net_speed", "usage_type"])
        #df_ip2location_csv = ip2location_csv_lookup(global_ips)

    if 'ipinfo' in lookup_list:
        print ("Running anycast lookup using ipinfo ...")
        ipinfo_results=[]
        ipinfo_results.extend(global_ips.Source.apply(ipinfo))
        df_ipinfo = pd.DataFrame(ipinfo_results,columns=["Source","Anycast"])


    if 'censys' in lookup_list:
        print ("Running open ports queries using Censys ...")
        censys_results=[]
        censys_results.extend(global_ips.Source.apply(censys_query))
        df_censys = pd.DataFrame(censys_results, columns=["Source","Open_ports"])

    if 'shodan' in lookup_list:
        print ("Running OS & open ports queries using Shodan ...")
        shodan_results=[]
        shodan_results.extend(global_ips.Source.apply(shodan_query))
        df_shodan = pd.DataFrame(shodan_results, columns=["Source","OS","Open_ports"])

    if 'map' in lookup_list:
        print ("Generating a world map of public IPs in the fingerprint ...")
        map_plot = map_plot()
        
    if 'mlab' in lookup_list:
        print ("Running network speed measurement queries using M-LAB ...")
        if 'asn' not in lookup_list:
            bgp_update()
            asn_results = []
            asn_results.extend(global_ips.Source.apply(asn_lookup))
            df_asn = pd.DataFrame(asn_results, columns=["Source", "ASN"])

        mlab_results=[]
        mlab_results.extend(df_asn.ASN.apply(MLab))
        df_mlab = pd.DataFrame(mlab_results,columns=["ASN", "AS_Average_Upload_Mbps","AS_Average_Download_Mbps"])
        df_mlab = pd.merge(df_mlab, df_asn, on=["ASN"])

    fingerprint_json['attackers']={}
    fingerprint_json['amplifiers']={}

    for ip in attackers:
        fingerprint_extender(ip,'attackers')

    for ip in amplifiers:
        fingerprint_extender(ip,'amplifiers')

    with open('output/'+file.split('.')[0]+'_enriched.json', 'w') as fingerprint_new:
        json.dump(fingerprint_json, fingerprint_new)
