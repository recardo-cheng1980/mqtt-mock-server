const https = require('node:https');
const fs = require('node:fs');

// 1. Load your certificate and key files
const options = {
  //Server side
  key: fs.readFileSync('privkey.pem'),
  cert: fs.readFileSync('fullchain.pem'),

  //Auth the client CA
  ca: [
    fs.readFileSync('intermediate-ca.crt'),
    fs.readFileSync('root-ca.crt')
  ],
  requestCert: true,
  rejectUnauthorized: true
};

// 2. Create the HTTPS server
const server = https.createServer(options, (req, res) => {
  console.log("test mqtt server");
  res.writeHead(200);
  res.end('Secure connection established!\n');
});

// 3. Listen on port 443 (standard HTTPS) or 8443 for dev
server.listen(8443, () => {
  console.log('HTTPS server running on https://localhost:8443');
});
