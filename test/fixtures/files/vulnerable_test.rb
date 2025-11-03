# Test file with intentional security vulnerabilities
# This file is used to test the Code Security Scanner tool

class VulnerableController < ApplicationController
  # SQL Injection vulnerabilities
  def search_users
    # VULN: String concatenation in WHERE clause
    User.where("name = '" + params[:name] + "'")

    # VULN: String interpolation in find_by_sql
    User.find_by_sql("SELECT * FROM users WHERE email = '#{params[:email]}'")
  end

  # XSS vulnerabilities
  def display_content
    # VULN: Using html_safe on user input
    @content = params[:content].html_safe

    # VULN: Using raw with params
    @html = raw(params[:html])
  end

  # Command Injection vulnerabilities
  def execute_command
    # VULN: String concatenation in system()
    system("ls " + params[:directory])

    # VULN: String interpolation in backticks
    `cat #{params[:filename]}`

    # VULN: exec with user input
    exec("rm " + params[:file])
  end

  # Path Traversal vulnerabilities
  def read_file
    # VULN: Reading file from user input
    content = File.read(params[:filename])

    # VULN: Opening file from params
    file = File.open(params[:path])
  end

  # IDOR vulnerability
  def show_document
    # VULN: Direct object access without authorization
    @document = Document.find(params[:id])
  end

  # Hardcoded Secrets
  def connect_to_api
    # VULN: Hardcoded API key
    api_key = "sk_live_1234567890abcdef"

    # VULN: Hardcoded password
    password = "MyP@ssw0rd123"

    # VULN: Hardcoded database credentials
    db_url = "postgres://admin:secret123@localhost/mydb"
  end

  # JWT Issues
  def verify_token
    # VULN: JWT decode without signature verification
    payload = JWT.decode(params[:token], nil, false)

    # VULN: JWT using "none" algorithm
    token = JWT.encode(data, secret, algorithm: "none")
  end

  # Weak Cryptography
  def hash_password
    # VULN: Using MD5 for password hashing
    hashed = Digest::MD5.hexdigest(password)

    # VULN: Using SHA1
    digest = Digest::SHA1.hexdigest(data)

    # VULN: Insecure random number generation
    token = rand(1000000)
  end

  # Insecure Deserialization
  def load_data
    # VULN: Unsafe Marshal.load with user input
    data = Marshal.load(params[:data])

    # VULN: Unsafe YAML.load
    config = YAML.load(params[:config])
  end

  # Mass Assignment
  def update_user
    # VULN: Mass assignment without permit
    @user.update(params[:user])

    # VULN: Create without permit
    User.create(params[:user_data])
  end

  # Open Redirect
  def redirect_user
    # VULN: Redirect to user-controlled URL
    redirect_to params[:url]
  end
end
