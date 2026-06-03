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

    // AVC denial report store — Map<deviceId, AvcReport[]>, keeps last 100 reports per device
    const avcStore = new Map();

    // Persistent storage directory for AVC reports (survives server restarts)
    const AVC_DIR = path.join(__dirname, 'avc-reports');
    if (!fs.existsSync(AVC_DIR)) fs.mkdirSync(AVC_DIR, { recursive: true });

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
    app.use(express.json({ limit: '10mb' }));  // AVC reports can be large

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

    // ── SELinux AVC Denial Reporting Endpoints ──────────────────────────────
    // DUT posts JSON batches via HTTPS; no MQTT cert dependency required.

    // POST /api/avc-report  — receive AVC denial batch from any device
    app.post('/api/avc-report', (req, res) => {
      const report = req.body;

      if (!report || !report.device_id) {
        return res.status(400).json({ error: 'Missing required field: device_id' });
      }

      report.received_at = new Date().toISOString();
      const deviceId = report.device_id;

      if (!avcStore.has(deviceId)) avcStore.set(deviceId, []);
      const reports = avcStore.get(deviceId);
      reports.push(report);
      if (reports.length > 100) reports.shift();  // keep last 100 per device

      // Persist to disk: ./avc-reports/<deviceId>/<safe_timestamp>.json
      try {
        const safeTs = (report.upload_timestamp || report.received_at).replace(/[:.]/g, '-');
        const deviceDir = path.join(AVC_DIR, deviceId);
        if (!fs.existsSync(deviceDir)) fs.mkdirSync(deviceDir, { recursive: true });
        const filePath = path.join(deviceDir, `${safeTs}.json`);
        fs.writeFileSync(filePath, JSON.stringify(report, null, 2));
        console.log(`[AVC] Saved ${report.denial_count || 0} denials from ${deviceId} → ${path.basename(filePath)}`);
      } catch (e) {
        console.error('[AVC] Failed to persist report to disk:', e.message);
      }

      console.log(`[AVC] Received from ${deviceId}: ${report.denial_count || 0} unique types` +
                  ` (${report.raw_denial_count || '?'} raw records)` +
                  ` | policy v${report.selinux_policy_version}, wnc_local v${report.wnc_local_version || '?'}, mode: ${report.selinux_mode}`);
      res.json({ status: 'ok', unique_types: report.denial_count || 0, raw_records: report.raw_denial_count || 0 });
    });

    // GET /api/avc-report/:deviceId  — query stored reports for a specific device
    app.get('/api/avc-report/:deviceId', (req, res) => {
      const deviceId = req.params.deviceId;
      const reports = avcStore.get(deviceId) || [];
      res.json({
        device_id: deviceId,
        report_count: reports.length,
        reports
      });
    });

    // GET /api/avc-report  — summary of all devices with AVC data
    app.get('/api/avc-report', (req, res) => {
      const summary = [];
      for (const [deviceId, reports] of avcStore.entries()) {
        const latest = reports[reports.length - 1];
        summary.push({
          device_id: deviceId,
          report_count: reports.length,
          latest_upload: latest?.upload_timestamp,
          latest_received: latest?.received_at,
          latest_denial_count: latest?.denial_count,
          selinux_mode: latest?.selinux_mode,
          policy_version: latest?.selinux_policy_version,
          firmware_version: latest?.firmware_version
        });
      }
      res.json({ total_devices: summary.length, devices: summary });
    });

    // GET /api/avc-files  — list all device folders with file counts and latest report metadata
    app.get('/api/avc-files', (req, res) => {
      try {
        const devices = fs.existsSync(AVC_DIR)
          ? fs.readdirSync(AVC_DIR).filter(d => fs.statSync(path.join(AVC_DIR, d)).isDirectory())
          : [];
        const summary = devices.map(deviceId => {
          const deviceDir = path.join(AVC_DIR, deviceId);
          const files = fs.readdirSync(deviceDir).filter(f => f.endsWith('.json')).sort();
          const latest = files.length > 0 ? files[files.length - 1] : null;
          let latestMeta = {};
          if (latest) {
            try {
              const data = JSON.parse(fs.readFileSync(path.join(deviceDir, latest)));
              latestMeta = {
                upload_timestamp: data.upload_timestamp,
                denial_count: data.denial_count,
                selinux_mode: data.selinux_mode,
                selinux_policy_version: data.selinux_policy_version,
                wnc_local_version: data.wnc_local_version,
                firmware_version: data.firmware_version
              };
            } catch (_) {}
          }
          return { device_id: deviceId, file_count: files.length, latest_file: latest, ...latestMeta };
        });
        res.json({ total_devices: summary.length, devices: summary });
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    });

    // GET /api/avc-files/:deviceId  — list all report files for a specific device
    app.get('/api/avc-files/:deviceId', (req, res) => {
      const deviceDir = path.join(AVC_DIR, req.params.deviceId);
      if (!fs.existsSync(deviceDir)) return res.json({ device_id: req.params.deviceId, files: [] });
      try {
        const files = fs.readdirSync(deviceDir).filter(f => f.endsWith('.json')).sort().reverse();
        const fileList = files.map(f => {
          const fp = path.join(deviceDir, f);
          const stat = fs.statSync(fp);
          let meta = {};
          try {
            const data = JSON.parse(fs.readFileSync(fp));
            meta = { upload_timestamp: data.upload_timestamp, denial_count: data.denial_count,
                     selinux_mode: data.selinux_mode, wnc_local_version: data.wnc_local_version };
          } catch (_) {}
          return { filename: f, size_bytes: stat.size, ...meta };
        });
        res.json({ device_id: req.params.deviceId, file_count: fileList.length, files: fileList });
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    });

    // GET /api/avc-files/:deviceId/:filename  — download a specific report JSON file
    app.get('/api/avc-files/:deviceId/:filename', (req, res) => {
      const filePath = path.join(AVC_DIR, req.params.deviceId, req.params.filename);
      if (!fs.existsSync(filePath) || !req.params.filename.endsWith('.json')) {
        return res.status(404).json({ error: 'File not found' });
      }
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Content-Disposition', `attachment; filename="${req.params.filename}"`);
      fs.createReadStream(filePath).pipe(res);
    });

    // POST /api/avc-request/:deviceId  — request immediate upload from a device (via MQTT)
    app.post('/api/avc-request/:deviceId', (req, res) => {
      const deviceId = req.params.deviceId;
      const packet = {
        cmd: 'publish',
        qos: 1,
        topic: `kms/${deviceId}/avc-request`,
        payload: Buffer.from(JSON.stringify({ action: 'upload_now' })),
        retain: false
      };
      aedes.publish(packet, (err) => {
        if (err) return res.status(500).json({ status: 'error', message: err.message });
        console.log(`[AVC] Upload request sent to ${deviceId}`);
        res.json({ status: 'ok', message: `Upload request sent to ${deviceId}` });
      });
    });
    // ────────────────────────────────────────────────────────────────────────

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
