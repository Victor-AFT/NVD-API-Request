import os, json, csv
from datetime import datetime
from requests.exceptions import HTTPError
import requests, zipfile
import wget
from os import remove
import logging
import shutil

#sellama pywget el paquete
#REALIZAR PATH RELATIVOS
path_JSON='JSON\\'

now = datetime.now()
time = now.strftime("%m_%d_%Y_")

url='https://services.nvd.nist.gov/rest/json/cves/1.0/'
name_json="NVDT_"+time+".json"
file_name_csv="NVDT_DAILY.csv"
datos_cve=[]

list_cpe=[]
datos_cve_delimiter=[]

if not os.path.exists('nvdcve-1.1-modified.json.zip'):
    download_http = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip"
    try:
        wget.download(download_http)
    except:
        logging.basicConfig(filename='logs.log', encoding='utf-8', level=logging.WARNING)
        logging.warning('ERROR http 505')
    #response = requests.get(download_http,stream=True)

file_name_src_zip=""
if os.path.exists('nvdcve-1.1-modified.json.zip'):
    archivozip= zipfile.ZipFile("nvdcve-1.1-modified.json.zip", mode="r")
    file_name_src_zip = archivozip.namelist()
    try:
        archivozip.extractall()
    except:
        pass
    archivozip.close()
    remove('nvdcve-1.1-modified.json.zip')




def recoge_fabricante_cpe23uri(lista):
    separador=":"
    separado=lista.split(separador)
    return separado[3]

def recoge_firmware_cpe23uri(lista):
    separador=":"
    separado=lista.split(separador)
    return separado[4]

def get_http_and_exportJSON(url,NameJson):
    try:
        response = requests.get(url)
        response.raise_for_status()
        jsonResponse = response.json()
        file = open(NameJson, "w")
        json.dump(jsonResponse,file)
        file.close()
    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')

#if not os.path.exists(name_json):
    #get_http_and_exportJSON(url,name_json)

#if not os.path.exists(file_name_csv):
 #  NOMBRE_COLUMNAS = 'ID,PUBLISHEDATE,[REFERENCES],DESCRIPTION,VECTORSTRING,BASESCORE,VERSION,[VULNERABLE,FABRICANTE,FIRMWARE,CPE],VERSIONEND;\n'
  # datos_cve.append(NOMBRE_COLUMNAS)


f = open(file_name_src_zip[0],encoding='utf-8')
data = json.load(f)
cve=data['CVE_Items']

myFile = open(file_name_csv, 'a', encoding='utf-8',newline='')
writer = csv.writer(myFile)


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
        list_references = ['https://No exists url']
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
    datos_cve.append(replace_description)

    # IMPACT
    check_impact = data['CVE_Items'][cve_n]['impact']
    if not check_impact:
        noDataImpact = 0
        NoImpact = ['No exists impact']
        datos_cve.append(NoImpact)
    else:
        noDataImpact = 1
        impact_baseMetricV3_vectorstring = data['CVE_Items'][cve_n]['impact']['baseMetricV3']['cvssV3']['vectorString']
        impact_baseMetricV3_basescore = data['CVE_Items'][cve_n]['impact']['baseMetricV3']['cvssV3']['baseScore']
        impact_baseMetricV3_version = data['CVE_Items'][cve_n]['impact']['baseMetricV3']['cvssV3']['version']

        datos_cve.append(impact_baseMetricV3_version)
        datos_cve.append(impact_baseMetricV3_vectorstring)
        datos_cve.append(impact_baseMetricV3_basescore)

    # NODES
    check_configuration_nodes = data['CVE_Items'][cve_n]['configurations']['nodes']

    if not check_configuration_nodes :
        noDataNodes = 0
        NoNodes = ['No exists Nodes']
        datos_cve.append(NoNodes)
    else:
        noDataNodes = 1
        for n in range(len(check_configuration_nodes)):

            configuration_nodes_operator = data['CVE_Items'][cve_n]['configurations']['nodes'][n]['operator']

            if configuration_nodes_operator == "OR":
                longitud_cpeMatch = data['CVE_Items'][cve_n]['configurations']['nodes'][n]['cpe_match']
                for cpe in range(len(longitud_cpeMatch)):

                    versionStart = ""
                    versionEnd = ""
                    nodes_cpe23uri = ""
                    fabricante = ""
                    firmware = ""
                    for k, v in data['CVE_Items'][cve_n]['configurations']['nodes'][n]['cpe_match'][cpe].items():

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
                configuration_nodes_children = data['CVE_Items'][cve_n]['configurations']['nodes'][n]['children']

                for c in range(len(configuration_nodes_children)):
                    # print("children")
                    longitud_nodes_children = data['CVE_Items'][cve_n]['configurations']['nodes'][n]['children'][c][
                        'cpe_match']
                    # print("LONGITUD: ",len(longitud_nodes_children))
                    for cpe_children in range(len(longitud_nodes_children)):

                        cversionStart = ""
                        cversionEnd = ""
                        cnodes_cpe23uri = ""
                        cfabricante = ""
                        cfirmware = ""
                        concat_cpe = ""
                        for ck, cv in \
                        data['CVE_Items'][cve_n]['configurations']['nodes'][n]['children'][c]['cpe_match'][
                            cpe_children].items():

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

    datos_cve = []

f.close()
os.rename(file_name_src_zip[0], name_json)
#print("rutal actual: ",os.getcwd())
shutil.move(os.getcwd()+'\\'+name_json,path_JSON)











