import re
import joblib

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

def lexical_analyzer(mensaje):
    # Define patterns for common spam, phishing, and CEO fraud terms
    english_patterns = {
        'spam': r"(free|money|offer|click|now|urgent|limited time|unsubscrib)",
        'phishing': r"(verify|account|login|password|credit card|bank)",
        'ceo_fraud': r"(transfer|payment|urgent|confidential|CEO|finance)"
    }

    spanish_patterns = {
        'spam': r"(gratis|dinero|oferta|haga clic|ahora|urgente|limitado|cancelar suscripción)",
        'phishing': r"(verificar|cuenta|inicio de sesión|contraseña|tarjeta de crédito|banco)",
        'ceo_fraud': r"(transferir|pago|urgente|confidencial|CEO|finanzas)"
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

    return peligrosidad

def ia_model_analyzer (mensaje):
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
    print(new_text)
    print(predicted)
    return peligrosidad