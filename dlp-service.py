# app.py
from flask import Flask, request, jsonify
import re
import json
from datetime import datetime

app = Flask(__name__)

# Simple patterns for sensitive data detection
PATTERNS = {
    'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'api_key': r'\b[A-Za-z0-9]{32,}\b'
}

@app.route('/scan', methods=['POST'])
def scan_content():
    content = request.json.get('content', '')
    findings = []
    
    for data_type, pattern in PATTERNS.items():
        matches = re.finditer(pattern, content)
        for match in matches:
            findings.append({
                'type': data_type,
                'value': match.group(),
                'position': match.span(),
                'timestamp': datetime.utcnow().isoformat()
            })
    
    return jsonify({
        'scan_id': datetime.utcnow().timestamp(),
        'findings': findings,
        'total_findings': len(findings)
    })

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
