
import os, json, csv
from datetime import datetime
#from requests.exceptions import HTTPError
import zipfile
import wget
from os import remove
import logging
import shutil


#REALIZAR PATH RELATIVOS
path_JSON_files='JSONS\\'

now = datetime.now()
time = now.strftime("%m_%d_%Y_")

knowexploitdvuln="known_exploited_vulnerabilities.csv"
csv_cisa='known_exploited_vulnerabilities_cisa.csv'
name_json="NVDT_"+time+".json"
file_name_csv="Z:\\NVDT_DAILY.csv"
file_name_csvSO="Z:\\NVDT_DAILY_SO.csv"
datos_cve=[]

list_cpe=[]
datos_cve_delimiter=[]
nvdcve2023='nvdcve-1.1-2023.json.zip'
nvdcveModified='nvdcve-1.1-modified.json.zip'
if not os.path.exists(nvdcveModified):
    download_http = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip"
    #download_http = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.zip"
    try:
        wget.download(download_http)
    except:
        logging.basicConfig(filename='logs.log', encoding='utf-8', level=logging.WARNING)
        logging.warning('ERROR http 505')
    #response = requests.get(download_http,stream=True)

file_name_src_zip=""
if os.path.exists(nvdcveModified):
    archivozip= zipfile.ZipFile(nvdcveModified, mode="r")
    file_name_src_zip = archivozip.namelist()
    try:
        archivozip.extractall()
    except:
        pass
    archivozip.close()
    remove(nvdcveModified)


if os.path.exists(csv_cisa):
    remove(csv_cisa)

if os.path.exists(name_json):
    remove(name_json)


def recoge_fabricante_cpe23uri(lista):
    separador=":"
    separado=lista.split(separador)
    return separado[3]

def recoge_firmware_cpe23uri(lista):
    separador=":"
    separado=lista.split(separador)
    return separado[4]


f = open(file_name_src_zip[0],encoding='utf-8')
data = json.load(f)
cve=data['CVE_Items']

myFile = open(file_name_csv, 'w', encoding='utf-8',newline='')
writer = csv.writer(myFile)

myFileSO = open(file_name_csvSO, 'w', encoding='utf-8',newline='')
writerSO = csv.writer(myFileSO)

noDataImpact=0
noDataNodes=0
for cve_n in range(len(cve)):

    cve_id = data['CVE_Items'][cve_n]['cve']['CVE_data_meta']['ID']
    cve_lastModifiedDate = data['CVE_Items'][cve_n]['lastModifiedDate']
    cve_publishedDate = data['CVE_Items'][cve_n]['publishedDate']

    if not cve_id and not cve_lastModifiedDate and not cve_publishedDate:
        nocve='No exists cve'
        nolastdate="No exists Last Modified Date"
        nopublishdate='No exists Published Date'
        datos_cve.append(nocve)
        datos_cve.append(nolastdate)
        datos_cve.append(nopublishdate)

    else:
        # CVE 2022-0906
        datos_cve.append(cve_id)
        # lastModifiedDate
        datos_cve.append(cve_lastModifiedDate)
        # publishedDate
        datos_cve.append(cve_publishedDate)

    # REFERENCES URL
    references = data['CVE_Items'][cve_n]['cve']['references']['reference_data']
    #CVE-2019-20417
    list_references = []
    if not references:
        list_references = ['https://WAITING_SOLUTIONS']
        datos_cve.append(list_references)

    else:

        for r in range(len(references)):
            # references_refsource = data['result']['CVE_Items'][cve_n]['cve']['references']['reference_data'][r]['refsource']
            references_url = data['CVE_Items'][cve_n]['cve']['references']['reference_data'][r]['url']
            #print(references_url)
            list_references.append(str(references_url))

        datos_cve.append(list_references)
        list_references = []
    # DESCRIPTION
    description = data['CVE_Items'][cve_n]['cve']['description']['description_data'][0]['value']
    replace_description = str(description).replace(",", "")
    replace_saltos_lineas=str(replace_description).replace("\n","")
    replace_comillas_dobles=str(replace_saltos_lineas.replace('""',""))
    replace_https_descrip = str(replace_comillas_dobles.replace("https:", "h-t-t-p-s-:"))
    datos_cve.append(replace_https_descrip)


    # IMPACT
    check_impact = data['CVE_Items'][cve_n]['impact']


    if not check_impact:
        noDataImpact = 0
        NoImpact = ['WAITING CVSS']
        datos_cve.append(NoImpact)
    else:
        noDataImpact = 1

        impact_baseMetricV2='baseMetricV2'
        impact_baseMetricV3='baseMetricV3'


        for k, v in data['CVE_Items'][cve_n]['impact'].items():

            if k!=impact_baseMetricV3:
                impact_baseMetricV2_vectorstring = data['CVE_Items'][cve_n]['impact'][k]['cvssV2']['vectorString']
                impact_baseMetricV2_basescore = data['CVE_Items'][cve_n]['impact'][k]['cvssV2']['baseScore']
                impact_baseMetricV2_version = data['CVE_Items'][cve_n]['impact'][k]['cvssV2']['version']

                datos_cve.append(impact_baseMetricV2_version)
                datos_cve.append(impact_baseMetricV2_vectorstring)
                datos_cve.append(impact_baseMetricV2_basescore)

            else:
                impact_baseMetricV3_vectorstring = data['CVE_Items'][cve_n]['impact'][k]['cvssV3']['vectorString']
                impact_baseMetricV3_basescore = data['CVE_Items'][cve_n]['impact'][k]['cvssV3']['baseScore']
                impact_baseMetricV3_version = data['CVE_Items'][cve_n]['impact'][k]['cvssV3']['version']

                datos_cve.append(impact_baseMetricV3_version)
                datos_cve.append(impact_baseMetricV3_vectorstring)
                datos_cve.append(impact_baseMetricV3_basescore)


    # NODES
    check_configuration_nodes = data['CVE_Items'][cve_n]['configurations']['nodes']

    if not check_configuration_nodes :
        noDataNodes = 0
        NoNodes = ['AWAITING CPE']
        datos_cve.append(NoNodes)
    else:
        noDataNodes = 1
        #for n in range(len(check_configuration_nodes)):

        configuration_nodes_operator = data['CVE_Items'][cve_n]['configurations']['nodes'][0]['operator']

        #print("CPE OPERATOR", configuration_nodesL_operator)
        if configuration_nodes_operator == "OR":
            #longitud_cpeMatch = data['CVE_Items'][cve_n]['configurations']['nodes'][0]['cpe_match'][0]
            #for cpe in range(len(longitud_cpeMatch)):

            versionStart = ""
            versionEnd = ""
            nodes_cpe23uri = ""
            fabricante = ""
            firmware = ""
            #print("LONGITUD: ",data['CVE_Items'][cve_n]['configurations']['nodes'][0]['cpe_match'])
            check_configuration_nodes_0_cpematch=data['CVE_Items'][cve_n]['configurations']['nodes'][0]['cpe_match']
            if check_configuration_nodes_0_cpematch:
                for k, v in data['CVE_Items'][cve_n]['configurations']['nodes'][0]['cpe_match'][0].items():

                    if k == 'cpe23Uri':
                        nodes_cpe23uri = v
                        fabricante = recoge_fabricante_cpe23uri(nodes_cpe23uri)
                        firmware = recoge_firmware_cpe23uri(nodes_cpe23uri)
                    if k == 'versionStartIncluding':
                        versionStart = versionStart + str(v)
    
                    if k == 'versionEndExcluding':
                        versionEnd = versionEnd + str(v)
    
                list_cpe.append(fabricante)
                list_cpe.append(firmware)
                list_cpe.append(nodes_cpe23uri)
                list_cpe.append(versionStart)
                list_cpe.append(versionEnd)

        else:

            if not  data['CVE_Items'][cve_n]['configurations']['nodes'][0]['children']:
                puedenotenerchildren=""
            else:
                #print("CPE AND: ",data['CVE_Items'][cve_n]['configurations']['nodes'][0]['children'][0]['cpe_match'][0])
                # print("LONGITUD: ",len(longitud_nodes_children))
                #for cpe_children in range(len(longitud_nodes_children)):

                cversionStart = ""
                cversionEnd = ""
                cnodes_cpe23uri = ""
                cfabricante = ""
                cfirmware = ""
                concat_cpe = ""
                check_configuration_nodes_children_0_cpematch = data['CVE_Items'][cve_n]['configurations']['nodes'][0]['children'][0]['cpe_match']
                if check_configuration_nodes_children_0_cpematch:
                    for ck, cv in data['CVE_Items'][cve_n]['configurations']['nodes'][0]['children'][0]['cpe_match'][0].items():

                        if ck == 'cpe23Uri':
                            cnodes_cpe23uri = cv
                            cfabricante = recoge_fabricante_cpe23uri(cnodes_cpe23uri)
                            cfirmware = recoge_firmware_cpe23uri(cnodes_cpe23uri)
                        if ck == 'versionStartIncluding':
                            cversionStart = cversionStart + str(cv)

                        if ck == 'versionEndExcluding':
                            cversionEnd = cversionEnd + str(cv)

                    list_cpe.append(cfabricante)
                    list_cpe.append(cfirmware)
                    list_cpe.append(cnodes_cpe23uri)
                    list_cpe.append(cversionStart)
                    list_cpe.append(cversionEnd)

    datos_cve.append(list_cpe)
    list_cpe = []
    datos_cve.append(";")

    if noDataNodes == 1 and noDataImpact == 1:
        # print("existe cpe")
        # print(datos_cve)
        writer.writerow(datos_cve)
        writerSO.writerow(datos_cve)

    #writer.writerow(datos_cve)
    #writerSO.writerow(datos_cve)
    datos_cve = []


f.close()

path_JSONS='JSONS'
isExist_directory_jsons=os.path.exists(path_JSONS)
isExist_file_jsons=os.path.exists(path_JSON_files+name_json)

if not isExist_directory_jsons:
    os.mkdir('JSON')

os.rename(file_name_src_zip[0], name_json)
if not isExist_file_jsons:
    shutil.move(name_json, path_JSON_files)
else:
    remove(name_json)



download_http_cisa = "https://www.cisa.gov/sites/default/files/csv/"+str(knowexploitdvuln)
try:
    wget.download(download_http_cisa)
except:
    logging.basicConfig(filename='logs_cisa.log', encoding='utf-8', level=logging.WARNING)
    logging.warning('ERROR http 505')


file_csv_cisa=open(csv_cisa,'w',encoding='utf-8', newline='')
writer_file_csv_cisa=csv.writer(file_csv_cisa)


with open(knowexploitdvuln, 'r', encoding='utf8') as csvfile:
    reader = csv.reader(csvfile, delimiter=',',lineterminator='\n')
    for row in reader:
        writer_file_csv_cisa.writerow(row)

if os.path.exists(knowexploitdvuln):
    os.remove(knowexploitdvuln)



