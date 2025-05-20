import os
import re
import ast
from flask import Flask, request, jsonify, redirect, session, url_for
from dotenv import load_dotenv
import subprocess
from authlib.integrations.flask_client import OAuth
import uuid
import requests
import json

oauth = OAuth()

load_dotenv()

app = Flask(__name__)

# Removed Hard-coded password and load environtmet variable
app.secret_key = os.getenv("SECRET", "fallback_random_secret")

# OIDC setup
oauth = OAuth(app)
oauth.register(
    name='keycloak',
    client_id='intranet',
    client_kwargs={'scope': 'openid profile'},
    server_metadata_url=os.getenv('OIDC_DISCOVERY_URL'),
)


# Validate token
def token_validation(token):
   if not token:
      return jsonify({"result": "token"})

   keycloak_url = "http://54.234.242.39:8080/realms/wk8app/protocol/openid-connect/userinfo"
   headers = {"Authorization": f"Bearer {token}"}
    
   response = requests.get(keycloak_url, headers=headers)

   if response.status_code != 200:
        return jsonify({"result": "invalid"})
   
   return jsonify({"result": "success"})

@app.route('/login')
def login():

    int_nonce = str(uuid.uuid4())
    session["nonce"] = int_nonce

    redirect_uri = url_for('auth', _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri, nonce=int_nonce)


@app.route('/auth')
def auth():
    code = request.args.get("code") 
    if not code:
       return jsonify({"Error:" "Missing authorization code"}), 400

    try:
        token = oauth.keycloak.authorize_access_token()
        nonce = session.pop("nonce", None)

        if not token:
           return jsonify({"Error:" "Token exchange failed"}), 400

        user_info = oauth.keycloak.parse_id_token(token, nonce=nonce)

        session['token'] = token['access_token']
        session['user'] = user_info
        return redirect('/')
    
    except Exception as e:
        return f"Error: {e}", 500  


@app.route('/')
def hello():
    if 'user' not in session:
        return redirect(url_for('login'))

    user = session['user']
    name=user.get('name',user.get('preferred_username', 'none'))
    token=session.get('token')

    response=token_validation(token)
    check=response.get_json()

    if check["result"] == "token":
        return jsonify({"error": "Unauthorized"}), 400
    elif check["result"] == "invalid":
        return jsonify({"error": "Invalid token"}), 400
    elif check["result"] == "success":
       return f"Hello, {name}, You have successfully logged in! <br><br> Retrieved access token: {token}" #<br><br> Retrieved access token: {token}
    else:
       return jsonify({"error": "Something went wrong"}), 400

# Fix command injection vulnerability
@app.route('/ping')
def ping():
    if 'user' not in session:
        return redirect(url_for('login'))
    token=session.get('token')
    

    response=token_validation(token)
    check=response.get_json()

    if check["result"] == "token":
        return jsonify({"error": "Unauthorized"}), 400
    elif check["result"] == "invalid":
        return jsonify({"error": "Invalid token"}), 400
    elif check["result"] == "success":
       ip = request.args.get('ip')
       if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", ip):
          return jsonify({"error": "Invalid IP address"}), 400
    
       # Fix unsafe command execution
       result = subprocess.check_output(["ping", "-c", "1", ip], shell=False)
       return result
    else:
       return jsonify({"error": "Something went wrong"}), 400


# Fix Insecure use of eval
@app.route('/calculate')
def calculate():
    if 'user' not in session:
        return redirect(url_for('login'))
    token=session.get('token')

    response=token_validation(token)
    check=response.get_json()

    if check["result"] == "token":
        return jsonify({"error": "Unauthorized"}), 400
    elif check["result"] == "invalid":
        return jsonify({"error": "Invalid token"}), 400
    elif check["result"] == "success":
       expression = request.args.get('expr')
       if not expression:
          return jsonify({"error": "You must enter an expression"}), 400
    
       if not re.fullmatch(r"[0-9+\-*/(). ]+", expression):
          return jsonify({"error": "Invalid Expression Entered"}), 400
       try:
          # Fix Dangerous use of eval
          result = ast.literal_eval(expression)
          return str(result)
       except Exception as e:
         return jsonify({"error": f"Failed:{e}"}), 400
    else:
       return jsonify({"error": "Something went wrong"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
