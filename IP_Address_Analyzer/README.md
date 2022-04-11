<p align="center"><img width=30.5% src="https://github.com/ddos-clearing-house/ddos_dissector/blob/3.0/media/header.png?raw=true"></p>


 <p align="center">
  <img width=30.5% src="https://github.com/ddos-clearing-house/dddosdb-in-a-box/blob/master/imgs/concordia-logo.png?raw=true">
 <p align="center"><img width=30.5% src="https://github.com/ddos-clearing-house/dddosdb-in-a-box/blob/master/imgs/No-More-DDoS-2-removebg-preview.png?raw=true"></p>
</p>

## IP Address Analyzer - Overview

This script gets a json DDoS fingerprint file as input and adds metadata for the source IP addresses existing in the fingerprint by querying them against local and external databases. Results are written to a new fingerprint file with more entries for each IP address.


## How to start?

1. Clone the ip_address_analyzer source code

```bash
git clone https://github.com/ddos-clearing-house/supplementary_components.git

```
2. Create a virtual environment (optional) and install dependencies

```
python -m venv ./ip-analyzer
source ip-analyzer/bin/activate
pip install -r requirements.txt
```

3. Provide a raw fingerprint to be analyzed

This package is compatible with the fingerprints that have a similar syntax to ones produced as the output of running the <a href="https://github.com/ddos-clearing-house/ddos_dissector">DDoS Dissector</a> component. Sample input fingerprints are provided in the <a href="https://github.com/ramin-y/IP_Address_Analyzer/tree/main/input">input</a> directory of the repository.

4. Run the software
```
chmod +x ip_analyzer.py
./ip_analyzer.py --input /path/to/input/fingerprint.json
```

4. Select the desired lookups to run from the menu. Some of the lookups require you to have api keys for the corresponding service and others run without any prerequisites. Check <a href="https://github.com/ddos-clearing-house/supplementary_components/blob/master/IP_Address_Analyzer/README.md#supported-lookups">Supported lookups</a> for more details.


5. Check the generated fingerprint (json file). 

The enriched fingerprints are stored in the <a href="https://github.com/ramin-y/IP_Address_Analyzer/tree/main/output">output</a> directory of the repository. You might use any tool to explore the additional metadata in the generated fingerprint.


## Supported lookups:

1. IP address type: <a href="https://docs.python.org/3/library/ipaddress.html#module-ipaddress">ipaddress</a> library of python is used to infer the type for each IP address existing in the fingerprint. This step is a preliminary step to run the follow up lookups and thus is set to always run as the first test. Besides, this is helpful first step for deploying mitigation rules on operational networks. For example, randomly spoofed DDoS attacks might include private IP ranges which should already be dropped at the edge router anyway, as they are not supposed to originate outside a network.

2. Autonomous System Number (ASN): This is based on the BGP data provided by the <a href="http://www.routeviews.org/routeviews/">Routeviews</a> project and adds the ASN field to the fingerprint. This can be used to infer whether some networks contribute more than others to a specific attack. 

3. Geo-IP: <a href="https://lite.ip2location.com/database">IP2Location LITE</a> database (free) is used in this step to extract the geolocation details as well as the usage type corresponding to the IP address. Currently <a href="https://lite.ip2location.com/database/ip-country-region-city-latitude-longitude-zipcode-timezone">DB11</a> and <a href="https://lite.ip2location.com/database/px10-ip-proxytype-country-region-city-isp-domain-usagetype-asn-lastseen-threat-residential">PX10</a> databases can be downloaded for free. The download token can be found <a href="https://lite.ip2location.com/file-download">here</a>.

4. Geo-IP:  <a href="https://www.ip2location.com/database">IP2Location</a> database (licensed) is used in this step to extract the geolocation details as well as the usage type corresponding to the IP address. BIN database files (IP2location DB and/or IP2Proxy PX) need to be stored in the corresponding folders as two sample files <a href="https://github.com/ramin-y/IP_Address_Analyzer/tree/main/data/ip2location">IP-COUNTRY-SAMPLE.BIN</a> and <a href="https://github.com/ramin-y/IP_Address_Analyzer/tree/main/data/ip2proxy">IP2PROXY-IP-COUNTRY.BIN</a>.   

5. Anycast address usage: <a href="https://ipinfo.io/">ipinfo</a> is used to infer whether the attacker IP resides is an "Anycast" IP address. Anycast addresses are addresses that are shared among multiple systems to improve the performance.

6. Open ports: Two Internet scanning services of <a href="https://censys.io/">Censys</a> and  <a href="https://shodan.io/">Shodan</a> are used to infer the open ports of the attacking hosts. The first time you try a lookup using one of these databases, you will be prompted to provide the coresponding api keys.

7. Operating System: Shodan database is used to lookup the operating system (if such info exists) of the attacker hosts. As mentioned above, an api key is needed to run the lookups.   

8. Map plot: Plots a world map plot of the IP addresses of attacker nodes in the fingerprint using the <a href="https://ipinfo.io/tools/map">Map IPs</a> tool of <a href="https://ipinfo.io/">ipinfo</a>.

9. M-LAB: Performs a network speed lookup using dat from <a href="https://www.measurementlab.net/">Measurement Lab</a>. Currently the lookups are done for the ASN average speed. This can be in practice a very coase-grained estimate for a single host. However, this is done as the coverage of the M-Lab data is too low at the moment.

