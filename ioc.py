import requests
import os

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
UNDERLINE = "\033[4m"
REVERSED = "\033[7m"
BLACK = "\033[30m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"

def consulta_virustotal(ioc, api_key):
    if ioc.count('.') == 3:  
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
    else:  
        url = f"https://www.virustotal.com/api/v3/domains/{ioc}"  
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        return {
            "country": data['data']['attributes'].get('country', 'N/A'),
            "continent": data['data']['attributes'].get('continent', 'N/A'),
            "malicious": data['data']['attributes']['last_analysis_stats'].get('malicious', 0),
            "suspicious": data['data']['attributes']['last_analysis_stats'].get('suspicious', 0),
            "whois": data['data']['attributes'].get('whois', 'N/A'),
            "as_owner": data['data']['attributes'].get('as_owner', 'N/A'),
            "tags": data['data']['attributes'].get('tags', 'N/A'),
        }
    return {}

def consulta_abuseipdb(ioc, api_key):
    url = f"https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    querystring = {"ipAddress": ioc}

    response = requests.get(url, headers=headers, params=querystring)
    if response.status_code == 200:
        data = response.json()
        keys_to_access = ["abuseConfidenceScore", "ipAddressIsPublic", "usageType", "isTor", "domain", "totalReports", "hostnames"]
        abuseipdb_info = {}
        for key in keys_to_access:
            value = data["data"].get(key, "N/A")
            abuseipdb_info[key] = value
        return abuseipdb_info
    return {}

def limpar_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    limpar_console()
    print(f"\n{BOLD}")
    title = """
▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌
▐██╗ ██████╗  ██████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗▌
▐██║██╔═══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║▌
▐██║██║   ██║██║         ███████╗██║     ███████║██╔██╗ ██║▌
▐██║██║   ██║██║         ╚════██║██║     ██╔══██║██║╚██╗██║▌
▐██║╚██████╔╝╚██████╗    ███████║╚██████╗██║  ██║██║ ╚████║▌
▐╚═╝ ╚═════╝  ╚═════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝▌
▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌
"""
    
    print(title) 
    ioc = input("Digite o IOC (IPv4, domínio, URL, etc.): ")
    virustotal_api_key = "YOUR API KEY"
    abuseipdb_api_key = "YOUR API KEY "
    limpar_console()
    print(title)
    
    # Script (Infos Gerais) --------------------------
    print(f"\n{YELLOW}====== Gereral =======")
    print(f"\nIOC: {ioc}")
    tipo_ioc = "IPV4" if ioc.count('.') == 3 else "Domínio/URL"
    print(f"Tipo de IOC: {tipo_ioc}")
    virustotal_info = consulta_virustotal(ioc, virustotal_api_key)
    print(f"Pais: {virustotal_info.get('country', 'N/A')}")
    print(f"Provedor: {virustotal_info.get('as_owner', 'N/A')}") 

    # Reputação --------------------------------------
    print(f"\n{BOLD}======== Reputacao =========")
    print(f"\n{RED}>>--> Virus total <--<<") 
    print(f"\n{YELLOW}Nivel Malicioso: {virustotal_info.get('malicious', 'N/A')} ")
    print(f"Nivel Suspeito: {virustotal_info.get('suspicious', 'N/A')}")
    print(f"Tags: {virustotal_info.get('tags', 'N/A')}")

    # Apenas consulta AbuseIPDB se for um IP
    if tipo_ioc == "IPV4":
        abuseipdb_info = consulta_abuseipdb(ioc, abuseipdb_api_key)
        print(f"\n{RED}>>--> AbuseIPDB <--<<") 
        print(f"\n{YELLOW}Score de Risco: {abuseipdb_info.get('abuseConfidenceScore', 'N/A')}%")
        print(f"usageType: {abuseipdb_info.get('usageType', 'N/A')}")
        print(f"Is TOR: {abuseipdb_info.get('isTor', 'N/A')}")
        print(f"Total Reports: {abuseipdb_info.get('totalReports', '0')}")
        print(f"Domain: {abuseipdb_info.get('domain', '0')}")
        print(f"Hosts: {abuseipdb_info.get('hostnames', '0')}")

    print(f"\n{BOLD}===============================================")
    print(f"\nPress ENTER to consultar novamente ou CTRL+C para sair")
    print(f"\n{BOLD}===============================================")
    input("")
    main()

if __name__ == "__main__":
    main()
