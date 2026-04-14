const tls = require('tls');
const fs = require('fs');
const path = require('path');

// 2. 變更：必須使用 async 函數來包裝初始化邏輯
async function startMqttServer() {
  try {
    // 1. 變更：使用動態 import() 載入 ESM 模組
    const { Aedes } = await import('aedes');
    const express = (await import('express')).default;

    // 3. 變更：改用 await Aedes.createBroker() 進行非同步初始化
    const aedes = await Aedes.createBroker();

    const options = {
  	key: fs.readFileSync('./certs/privkey.pem'),
	cert: fs.readFileSync('./certs/fullchain.pem'),
	ca: [
		fs.readFileSync('./certs/intermediate-ca.crt'),
		fs.readFileSync('./certs/root-ca.crt')
 	],
      // mTLS 核心設定
      requestCert: true,
      rejectUnauthorized: true
    };

    const server = tls.createServer(options, aedes.handle);
    const PORT = 8443;

    // Track connected MQTT clients
    const connectedClients = new Map();

    server.listen(PORT, function () {
      console.log(`MQTT mTLS 伺服器已啟動，正在監聽連接埠 ${PORT}`);
    });

    aedes.on('client', function (client) {
	const clientInfo = {
		id: client.id,
		connected_at: new Date().toISOString(),
		tls: false,
		cert: null
	};

	if (client.conn && typeof client.conn.getPeerCertificate === 'function') {

		// 傳入 true 參數可以取得包含完整憑證鏈的詳細資訊 (可選)
		const cert = client.conn.getPeerCertificate();

		// 檢查憑證是否為空
		if (cert && Object.keys(cert).length > 0) {
			console.log(`[mTLS 驗證成功] 客戶端 ID: ${client.id}`);

      // 1. 取得 Node.js 原始的連續大寫序號字串
      const rawSerial = cert.serialNumber;

      // 2. 轉換為小寫，並使用正規表達式每兩個字元插入一個冒號
      let formattedSerial = '';
      if (rawSerial) {
        formattedSerial = rawSerial
          .toLowerCase()
          .match(/.{1,2}/g)
          .join(':');
      }

      // 3. 輸出與 DUT 完全相同的格式
      console.log(`  - 憑證序號 (Serial): ${formattedSerial}`);

			// 記錄憑證的關鍵欄位
			console.log(`  - 設備/通用名稱 (CN):`, cert.subject.CN);
			console.log(`  - 頒發機構 (Issuer CN):`, cert.issuer.CN);
			console.log(`  - 憑證指紋 (Fingerprint):`, cert.fingerprint);
			console.log(`  - 有效期限至:`, cert.valid_to);

			if (cert.subjectaltname) {
				console.log(`  - 替代名稱 (SAN):`, cert.subjectaltname);
			}

			clientInfo.tls = true;
			clientInfo.cert = {
				cn: cert.subject.CN,
				issuer: cert.issuer.CN,
				serial: formattedSerial,
				fingerprint: cert.fingerprint,
				valid_to: cert.valid_to,
				san: cert.subjectaltname || ''
			};
		} else {
			console.warn(`[警告] 客戶端 ${client.id} 未提供憑證。`);
		}
	}
	else {
		console.log(`客戶端已連線: ${client.id} (非 TLS 連線)`);
	}

	connectedClients.set(client.id, clientInfo);
    });

    aedes.on('clientDisconnect', function (client) {
      console.log(`客戶端已斷線: ${client ? client.id : client}`);
      if (client) {
        connectedClients.delete(client.id);
      }
    });

    aedes.on('publish', function (packet, client) {
      if (client) {
        console.log(`收到來自 ${client.id} 的訊息，主題: ${packet.topic}`);
      }
    });

    server.on('error', function (err) {
      console.error('伺服器發生錯誤:', err);
    });

    //The http part
    const app = express();
    app.use(express.json());

    // Version endpoint — update version in package.json on every code change
    const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
    const startedAt = new Date().toISOString();
    app.get('/version', (req, res) => {
      res.json({
        version: pkg.version,
        started: startedAt
      });
    });

    // MQTT client connection status endpoint
    app.get('/api/clients', (req, res) => {
      const clients = Array.from(connectedClients.values());
      res.json({
        total: clients.length,
        clients: clients
      });
    });

    // 建立觸發輪替的 HTTP POST 路由
    app.post('/api/rotate/:deviceId', (req, res) => {
      const deviceId = req.params.deviceId;
      const requestPayload = req.body; // 取得 HTTP 傳入的 JSON

      // 檢查 Payload 格式是否正確
      if (!requestPayload || !requestPayload.service) {
        return res.status(400).json({ error: '無效的請求：缺少必要的 JSON 欄位' });
      }

      // 構建要發布的 MQTT 封包
      const packet = {
        cmd: 'publish',
        qos: 1, // 使用 QoS 1 確保指令到達
        topic: `kms/${deviceId}/rotate`,
        payload: Buffer.from(JSON.stringify(requestPayload)),
        retain: false
      };

      // 透過 Aedes 內部 API 直接發布訊息
      aedes.publish(packet, function (err) {
        if (err) {
          console.error(`[HTTP 橋接] 觸發設備 ${deviceId} 輪替失敗:`, err);
          return res.status(500).json({ status: 'error', message: '內部 MQTT 轉發失敗' });
        }
        
        console.log(`[HTTP 橋接] 成功將輪替指令轉發至主題: ${packet.topic}`);
        res.status(200).json({ 
          status: 'ok', 
          message: `已觸發 ${deviceId} 的憑證輪替`,
          delivered_payload: requestPayload
        });
      });
    });

    // Docker pull endpoint — publishes to kms/<deviceId>/pull
    app.post('/api/pull/:deviceId', (req, res) => {
      const deviceId = req.params.deviceId;
      const requestPayload = req.body;

      if (!requestPayload || !requestPayload.image || !requestPayload.digest || !requestPayload.vault_path) {
        return res.status(400).json({ error: 'Missing required fields: image, digest, vault_path' });
      }

      const packet = {
        cmd: 'publish',
        qos: 1,
        topic: `kms/${deviceId}/pull`,
        payload: Buffer.from(JSON.stringify(requestPayload)),
        retain: false
      };

      aedes.publish(packet, function (err) {
        if (err) {
          console.error(`[HTTP Bridge] Failed to publish pull command for ${deviceId}:`, err);
          return res.status(500).json({ status: 'error', message: 'MQTT publish failed' });
        }

        console.log(`[HTTP Bridge] Pull command published to topic: ${packet.topic}`);
        res.status(200).json({
          status: 'ok',
          message: `Pull command sent to ${deviceId}`,
          delivered_payload: requestPayload
        });
      });
    });

    // KEK provision endpoint — publishes to kms/<deviceId>/provision
    app.post('/api/provision/:deviceId', (req, res) => {
      const deviceId = req.params.deviceId;
      const requestPayload = req.body;

      if (!requestPayload || !requestPayload.key_name || !requestPayload.key_data) {
        return res.status(400).json({ error: 'Missing required fields: key_name, key_data' });
      }

      const packet = {
        cmd: 'publish',
        qos: 1,
        topic: `kms/${deviceId}/provision`,
        payload: Buffer.from(JSON.stringify(requestPayload)),
        retain: false
      };

      aedes.publish(packet, function (err) {
        if (err) {
          console.error(`[HTTP Bridge] Failed to publish provision command for ${deviceId}:`, err);
          return res.status(500).json({ status: 'error', message: 'MQTT publish failed' });
        }

        console.log(`[HTTP Bridge] Provision command published to topic: ${packet.topic}`);
        res.status(200).json({
          status: 'ok',
          message: `KEK provision sent to ${deviceId}`,
          delivered_payload: requestPayload
        });
      });
    });

    // 3. 啟動 HTTP 伺服器 (強烈建議綁定 127.0.0.1 確保僅限本機存取)
    const HTTP_PORT = 3000;
    app.listen(HTTP_PORT, '0.0.0.0', () => {
      console.log(`HTTP 本機控制介面已啟動: http://127.0.0.1:${HTTP_PORT}`);
    });

  } catch (error) {
    console.error('Aedes Broker 初始化失敗:', error);
  }
}

startMqttServer();
