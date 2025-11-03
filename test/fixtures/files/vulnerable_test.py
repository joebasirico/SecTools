# Test file with intentional security vulnerabilities
# This file is used to test the Code Security Scanner tool

import os
import subprocess
import sqlite3
import pickle
import random

# SQL Injection vulnerabilities
def search_users(user_id):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # VULN: String formatting in SQL execute
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)

    # VULN: String concatenation in cursor.execute
    cursor.execute("SELECT * FROM users WHERE name = " + username)

# Command Injection vulnerabilities
def execute_command(directory):
    # VULN: String concatenation in os.system()
    os.system("ls " + directory)

    # VULN: String concatenation in subprocess
    subprocess.call("rm " + filename)

    # VULN: shell=True in subprocess
    subprocess.run(user_command, shell=True)

# Path Traversal
def read_file(filename):
    # VULN: Opening file from request
    with open(request.args.get("file"), 'r') as f:
        content = f.read()

# JWT Issues
def verify_token(token):
    import jwt

    # VULN: JWT decode without verification
    payload = jwt.decode(token, options={"verify_signature": False})

    # VULN: JWT decode with verify=False
    payload = jwt.decode(token, secret, verify=False)

# Weak Cryptography
def hash_password(password):
    import hashlib

    # VULN: Using MD5
    hashed = hashlib.md5(password.encode()).hexdigest()

    # VULN: Using SHA1
    digest = hashlib.sha1(data.encode()).hexdigest()

    # VULN: Insecure random number generation
    token = random.random()

# Hardcoded Secrets
# VULN: Hardcoded credentials
API_KEY = "sk_live_1234567890abcdef"
PASSWORD = "admin123"
DATABASE_URL = "postgres://user:password123@localhost/db"

# VULN: Private key in source
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----"""

# Insecure Deserialization
def load_data(data):
    # VULN: Unsafe pickle with user input
    obj = pickle.loads(request.data)

    # VULN: pickle.load with input
    result = pickle.load(input_stream)
