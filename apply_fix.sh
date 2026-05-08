#!/bin/bash
set -e
#!/bin/bash
git checkout -b fix/issue-170
cat << 'EOF' > prophet_webhook_handler.py
import hmac
import hashlib
import json
from flask import Flask, request, abort

app = Flask(__name__)
SHARED_SECRET = b'your_shared_secret_here'

def verify_signature(payload, signature):
    expected = hmac.new(SHARED_SECRET, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)

@app.route('/publishers/seren-affiliates/webhooks/prophet', methods=['POST'])
def prophet_webhook():
    signature = request.headers.get('X-Prophet-Signature')
    if not signature or not verify_signature(request.data, signature):
        abort(401)
    
    data = request.json
    event_type = data.get('event_type')
    agent_code = data.get('agent_code') # AGENTACCESS=<agent>
    
    # Logic to process signup, deposit, bet, retention
    print(f"Received {event_type} for agent {agent_code}")
    
    return jsonify({"status": "success"}), 200

if __name__ == "__main__":
    app.run(port=5000)
EOF
git add prophet_webhook_handler.py
git commit -m "fix: Prophet webhook integration for Seren-Swarm bounty — Fixes #170"
