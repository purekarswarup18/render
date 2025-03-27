from flask import Flask, request, jsonify, render_template
import pickle
import numpy as np
import re
from urllib.parse import urlparse

app = Flask(__name__)

# Load the trained model
with open("model_pkl", "rb") as file:
    model = pickle.load(file)


def extract_features(url):
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname if parsed_url.hostname else ""  # Ensure hostname is not None

    return np.array([
        # 1. Having IP Address
        1 if re.search(r'(([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\.'
                       r'([01]?\d\d?|2[0-4]\d|25[0-5])\.([01]?\d\d?|2[0-4]\d|25[0-5])\/)|'
                       r'((0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\.(0x[0-9a-fA-F]{1,2})\/)|'
                       r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url) else 0,

        # 2. Abnormal URL
        1 if hostname and re.search(hostname, url) else 0,

        # 3. Google Index (Default to 1, unless checked via API)
        1,

        # 4. Number of subdomains
        url.count('.'),

        # 5. WWW count
        url.count('www'),

        # 6. '@' count
        url.count('@'),

        # 7. Directory count
        url.count('/'),

        # 8. Embedded domains count
        url.count('//'),

        # 9. Suspicious words presence
        1 if any(word in url.lower() for word in ['paypal', 'login', 'bank', 'bonus']) else 0,

        # 10. Shortened URL detection
        1 if re.search(r'bit\.ly|goo\.gl|tinyurl|ow\.ly', url) else 0,

        # 11. HTTPS count
        url.count('https'),

        # 12. HTTP count
        url.count('http'),

        # 13. '%' count
        url.count('%'),

        # 14. '?' count
        url.count('?'),

        # 15. '-' count
        url.count('-'),

        # 16. '=' count
        url.count('='),

        # 17. URL Length
        len(url),

        # 18. Hostname Length
        len(hostname),

        # 19. First directory length
        len(parsed_url.path.split('/')[1]) if len(parsed_url.path.split('/')) > 1 else 0,

        # 20. Top-level domain length
        len(hostname.split('.')[-1]) if hostname else 0,

        # 21. Number of digits
        sum(c.isdigit() for c in url)
    ]).reshape(1, -1)

@app.route('/')
def home():
    return render_template('index.html')  # Render the HTML form

@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.form['url']
        features = extract_features(url)  # Convert URL to features
        prediction = model.predict(features)
        
        labels = ['Benign', 'Defacement', 'Phishing', 'Malware']
        result = labels[prediction[0]]

        return render_template('index.html', prediction_text=f"The URL is classified as: {result.upper()}")
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == "__main__":
    app.run(debug=True, port=5002)
