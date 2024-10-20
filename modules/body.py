import re
import joblib
import requests
import json
from modules.classes import MailServer, Mail, URL, engine_result, File, sandbox
import base64
import mimetypes
import os
from time import sleep

def get_url_file():
    import requests

    url = "https://www.virustotal.com/api/v3/files/upload_url"

    headers = {"accept": "application/json"}

    response = requests.get(url, headers=headers)

    return response.text

def url_vt_call(url):
    
    url_obj = URL()
    url_obj.name = url
    urlvt = "https://www.virustotal.com/api/v3/urls"

    payload = { "url": url }
    headers = {
        "accept": "application/json",
        "x-apikey": "",
        "content-type": "application/x-www-form-urlencoded"
    }

    response = requests.post(urlvt, data=payload, headers=headers)
    #response_json = json.loads(response)
    response_json = response.json()
    analysis_id = response_json['data']['links']['self']

    urlvt = analysis_id

    headers = {
        "accept": "application/json",
        "x-apikey": ""
    }
    sleep(15)
    response = requests.get(urlvt, headers=headers)

    #response_json = json.loads(response)
    response_json = response.json()
    url_obj.harm = int (response_json['data']['attributes']['stats']['harmless'])
    url_obj.malicious = int (response_json['data']['attributes']['stats']['malicious'])
    url_obj.suspicious = int(response_json['data']['attributes']['stats']['suspicious'])
    url_obj.undetected = int(response_json['data']['attributes']['stats']['undetected'])

    engines = response_json['data']['attributes']['results']
    # Iterate over the engines and create engine_result objects
    for engine, details in engines.items():
        name = details['engine_name']
        category = details['category']
        result = details['result']
        engine_result_obj = engine_result(name, category, result)
        url_obj.add_engine(engine_result_obj)
    
    return url_obj
   
"""
    url_id = base64.urlsafe_b64encode("http://www.somedomain.com/this/is/my/url".encode()).decode().strip("=")
    urlvt= "https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {
        "accept": "application/json",
        "x-apikey": ""
        }
    response = requests.get(urlvt, headers=headers)
    response_json = response.json()
    print(response_json)
 """   

def get_mime_type(file_path):
    # Guess the MIME type based on the file extension
    mime_type, _ = mimetypes.guess_type(file_path)
    return mime_type

def get_text_from_body(mensaje):
    # Extract the text from the email body
    email_body = ""

    if mensaje.is_multipart():
        for part in mensaje.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            # Extract text from HTML and plain text parts
            if "text/plain" in content_type and "attachment" not in content_disposition:
                email_body = part.get_payload(decode=False)
                break

    else:
        email_body = mensaje.get_payload(decode=False)
    
    return email_body

def lexical_analyzer(mensaje, correo):
    # Define patterns for common spam, phishing, and CEO fraud terms
    english_patterns = {
        'spam': r"\b(free|money|offer|click|now|urgent|limited time|unsubscrib)\b",
        'phishing': r"\b(verify|account|login|password|credit card|bank)\b",
        'ceo_fraud': r"\b(transfer|payment|urgent|confidential|CEO|finance)\b"
    }

    spanish_patterns = {
        'spam': r"\b(gratis|dinero|oferta|haga clic|ahora|urgente|limitado|cancelar suscripción)\b",
        'phishing': r"\b(verificar|cuenta|inicio de sesión|contraseña|tarjeta de crédito|banco)\b",
        'ceo_fraud': r"\b(transferir|pago|urgente|confidencial|CEO|finanzas)\b"
    }

    # Initialize counts for each category
    english_counts = {category: 0 for category in english_patterns}
    spanish_counts = {category: 0 for category in spanish_patterns}

    text=get_text_from_body(mensaje)
    # Convert text to lowercase for case-insensitive matching
    text_lower = text.lower()

    # Count occurrences of each pattern in English
    for category, pattern in english_patterns.items():
        matches = re.findall(pattern, text_lower)
        english_counts[category] = len(matches)

    # Count occurrences of each pattern in Spanish
    for category, pattern in spanish_patterns.items():
        matches = re.findall(pattern, text_lower)
        spanish_counts[category] = len(matches)

    english_total = sum(english_counts.values())
    spanish_total = sum(spanish_counts.values())

    total_percen= english_total / 0.1 + spanish_total / 0.1

    peligrosidad = total_percen * 10 / 100 #habria que cambiar el 10 por el peso que le queramos dar
    if english_total > 0 or spanish_total > 0:
        correo.fraudPatterns = True
    return peligrosidad

def ia_model_analyzer (mensaje, correo):
    peligrosidad = 0
    # Load the classifier
    classifier = joblib.load('modules/model/classifier_model.pkl')

    # Load the vectorizer
    vectorizer = joblib.load('modules/model/vectorizer.pkl')

    # Use the loaded model and vectorizer for prediction
    new_text=get_text_from_body(mensaje)
    documents = new_text.split("\n")
    X_new = vectorizer.transform([new_text])
    predicted = classifier.predict(X_new)
    label = predicted[0]
    if label == 'spam':
        peligrosidad = 10
        correo.spam_mail = True
    print(new_text)
    print(predicted)
    return peligrosidad

def URL_analysis(mensaje, correo):
    url_pattern = r'https?://\S+'

    email_body = get_text_from_body(mensaje)
    # Find all URLs in the email body
    urls = re.findall(url_pattern, email_body)

    
    for url in urls:
        url_obj = URL()
        url_obj = url_vt_call(url)
        correo.add_url(url_obj)
        if url_obj.malicious > 2 or url_obj.suspicious > 5:
            print("URL: "+url_obj.name+" peligrosa")
            correo.add_peligrosidad(15)
        else:
            print("URL: "+url_obj.name+" fuera de peligro, Malicious: "+str(url_obj.malicious)+" Harm: "+str(url_obj.harm))

def wait_analysis(url):
    headers = {
        "accept": "application/json",
        
        "x-apikey": ""
    }
    while True:
        print("WAITING FOR ANALYSIS REPORT")
        sleep(60)
        while True:
            response = requests.get(url, headers=headers)
            
            if response.json().get("data").get("attributes").get("status") == "completed":
                #print("response"+response.text)
                f_hash = response.json().get("meta").get("file_info").get("sha256")
                return f_hash

def FILE_analysis(url, file_path):
    fileAn = File()    
    #sand = sandbox()
    mime_type = get_mime_type(file_path)
    print(mime_type)
    current_dir = os.getcwd()
    file_path = os.path.join(current_dir, file_path)
    files = { "file": (os.path.basename(file_path), open(file_path, "rb"), mime_type) }
    print(files)
    headers = {
        "accept": "application/json",
        
        "x-apikey": ""
    }

    response = requests.post(url, files=files, headers=headers)

    response_json = response.json()
    analysis_id = response_json['data']['links']['self']
    print("analysis "+analysis_id)
    f_hash = wait_analysis(analysis_id)
    print ("hash "+f_hash)
    url = f"https://www.virustotal.com/api/v3/files/{f_hash}"
    headers = {"accept": "application/json",

            "x-apikey": ""
    }

    response = requests.get(url, headers=headers)

    #print(response.text)
    response_json = response.json()
    #print("1")
    fileAn.hash = response_json['data']['id']
    fileAn.name = response_json['data']['attributes']['meaningful_name']
     #print("2")
    fileAn.harm = int (response_json['data']['attributes']['last_analysis_stats']['harmless'])
    fileAn.malicious = int (response_json['data']['attributes']['last_analysis_stats']['malicious'])
    #print("3")    
    fileAn.suspicious = int(response_json['data']['attributes']['last_analysis_stats']['suspicious'])
    fileAn.undetected = int(response_json['data']['attributes']['last_analysis_stats']['undetected'])
    #print("4")

    engines = response_json['data']['attributes']['last_analysis_results']
    # Iterate over the engines and create engine_result objects
    for engine, details in engines.items():
        #print("5")
        name = details['engine_name']
        category = details['category']
        result = details['result']
        engine_result_obj = engine_result(name, category, result)
        fileAn.add_engine(engine_result_obj)
    
    fileAn.date = int(response_json['data']['attributes']['last_analysis_date'])
    fileAn.type = response_json['data']['attributes']['type_tag']
    #print("6")
    return fileAn
    if "sandbox_verdicts" in response_json['data']['attributes']:
        sand = response_json['data']['attributes']['sandbox_verdicts']
        for box, details in sand.items():
            #print("7")
            name = details["sandbox_name"]
            confidence = int(details["confidence"])
            category = details["category"]
            sandb = sandbox(name, confidence, category)
            if category == "malicious":
                sandb.malName = details["malware_names"]
                sandb.set_classification(details["malware_classification"])
            fileAn.add_sandbox(sandb)

    return fileAn

