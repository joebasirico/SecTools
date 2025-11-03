// Test file with intentional security vulnerabilities
// This file is used to test the Code Security Scanner tool

// SQL Injection vulnerabilities
function searchUsers(userId) {
  // VULN: String concatenation in SQL query
  db.query("SELECT * FROM users WHERE id = " + userId);

  // VULN: String concatenation in raw query
  sequelize.query.raw("SELECT * FROM users WHERE name = " + userName);
}

// XSS vulnerabilities
function displayContent(userInput) {
  // VULN: Setting innerHTML with variable
  document.getElementById('content').innerHTML = userInput;

  // VULN: document.write with variable
  document.write(userInput);

  // VULN: jQuery .html() with variable
  $('.content').html(userInput);

  // VULN: dangerouslySetInnerHTML in React
  return <div dangerouslySetInnerHTML={{__html: userContent}} />;
}

// Command Injection vulnerabilities
function executeCommand(directory) {
  const { exec } = require('child_process');

  // VULN: String concatenation in exec()
  exec("ls " + directory);

  // VULN: String template in exec()
  exec(`cat ${filename}`);
}

// Path Traversal
function readFile(filename) {
  const fs = require('fs');

  // VULN: Reading file from request
  fs.readFile(req.query.file, 'utf8', callback);
}

// JWT Issues
function verifyToken(token) {
  const jwt = require('jsonwebtoken');

  // VULN: JWT verify with empty secret
  const decoded = jwt.verify(token, "");

  // VULN: JWT using "none" algorithm
  const token = jwt.sign(payload, secret, { algorithm: "none" });
}

// Weak Cryptography
function generateToken() {
  // VULN: Using Math.random() for security
  const token = Math.random().toString(36);

  // VULN: Using MD5
  const hash = crypto.createHash('md5').update(password).digest('hex');
}

// Hardcoded Secrets
const config = {
  // VULN: Hardcoded API key
  apiKey: "sk_live_abc123xyz789",

  // VULN: Hardcoded password
  password: "admin123",

  // VULN: AWS Access Key
  awsKey: "AKIAIOSFODNN7EXAMPLE"
};

// Open Redirect
function handleRedirect(url) {
  // VULN: Location redirect from request
  window.location = req.query.redirect;
}

// Insecure Deserialization
function parseData(data) {
  // VULN: JSON.parse with request data (prototype pollution risk)
  const obj = JSON.parse(req.body.data);
}
