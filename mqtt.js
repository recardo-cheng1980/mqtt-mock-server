const tls = require('tls');
const https = require('node:https');
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

    // AVC denial report store — Map<deviceId, MergedState>
    // MergedState: { device_id, first/last_upload_timestamp, last_received_at, upload_count,
    //   total_raw_denials, firmware metadata fields, denialMap: Map<key, denialEntry> }
    const avcStore = new Map();
    const MERGED_FILENAME = 'avc-denials.json';

    // Persistent storage directory for AVC reports (survives server restarts)
    const AVC_DIR = path.join(__dirname, 'avc-reports');
    if (!fs.existsSync(AVC_DIR)) fs.mkdirSync(AVC_DIR, { recursive: true });

    // Dedup key — mirrors selinux-avc-reporter.py: (scontext, tcontext, tclass, sorted_perms)
    function denialKey(d) {
      const perms = Array.isArray(d.perms) ? [...d.perms].sort().join(',') : String(d.perms || '');
      return `${d.scontext}|${d.tcontext}|${d.tclass}|${perms}`;
    }

    // Lazy-load merged state from avc-denials.json on first POST for a device
    function loadMergedState(deviceId) {
      const filePath = path.join(AVC_DIR, deviceId, MERGED_FILENAME);
      if (!fs.existsSync(filePath)) return null;
      try {
        const disk = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        const denialMap = new Map();
        (disk.denials || []).forEach(d => denialMap.set(denialKey(d), d));
        return { ...disk, denialMap };
      } catch (e) {
        console.error(`[AVC] Failed to load merged state for ${deviceId}:`, e.message);
        return null;
      }
    }

    // Write merged state atomically (tmp → rename) to avc-denials.json
    function saveMergedState(merged) {
      const deviceDir = path.join(AVC_DIR, merged.device_id);
      if (!fs.existsSync(deviceDir)) fs.mkdirSync(deviceDir, { recursive: true });
      const denials = Array.from(merged.denialMap.values())
        .sort((a, b) => (b.occurrence_count || 0) - (a.occurrence_count || 0));
      const diskState = {
        device_id:                 merged.device_id,
        first_upload_timestamp:    merged.first_upload_timestamp,
        last_upload_timestamp:     merged.last_upload_timestamp,
        last_received_at:          merged.last_received_at,
        upload_count:              merged.upload_count,
        total_raw_denials:         merged.total_raw_denials,
        total_unique_denial_types: denials.length,
        firmware_version:          merged.firmware_version,
        fw_build:                  merged.fw_build,
        selinux_policy_version:    merged.selinux_policy_version,
        wnc_local_version:         merged.wnc_local_version,
        wnc_local_te_lines:        merged.wnc_local_te_lines,
        wnc_local_fc_lines:        merged.wnc_local_fc_lines,
        selinux_mode:              merged.selinux_mode,
        denials
      };
      const finalPath = path.join(deviceDir, MERGED_FILENAME);
      const tmpPath   = finalPath + '.tmp';
      fs.writeFileSync(tmpPath, JSON.stringify(diskState, null, 2));
      fs.renameSync(tmpPath, finalPath);
      return diskState;
    }

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

    // ── SSH Certificate Authority: user login cert signing ─────────────────
    // Signs SSH login certificates directly against Vault's SSH secrets
    // engine, using this server's OWN dedicated Vault credential — NOT any
    // device's TPM-provisioned AppRole. The DUT is never involved in this
    // request path at all; it only ever trusts the resulting CA public key
    // (fetched separately by kms-cert-manager's own read-only Vault call).
    // See docs/kms/ssh-ca-user-and-host-certs-plan.md in the uct-iq9075 repo.
    //
    // Required env vars (set via Portainer stack config — never commit
    // real values to this repo):
    //   VAULT_ADDR         e.g. https://vault.csyang.org
    //   VAULT_TOKEN        token scoped ONLY to ssh/sign/user-login —
    //                      must NOT be shared with any device's own AppRole
    //   VAULT_SSH_MOUNT    defaults to "ssh"
    //   VAULT_SSH_ROLE     defaults to "user-login"
    //   SSH_SIGN_API_KEY   shared secret required in the X-SSH-Sign-Key
    //                      header. If unset, this endpoint refuses every
    //                      request (fails closed) rather than silently
    //                      allowing unauthenticated issuance of human login
    //                      credentials — that blast radius is categorically
    //                      different from the other endpoints above.
    function vaultSshSign(publicKey, principal, engineerId, ttl) {
      return new Promise((resolve, reject) => {
        const vaultAddr = process.env.VAULT_ADDR;
        const vaultToken = process.env.VAULT_TOKEN;
        if (!vaultAddr || !vaultToken) {
          return reject(new Error('VAULT_ADDR/VAULT_TOKEN not configured on this server'));
        }
        const mount = process.env.VAULT_SSH_MOUNT || 'ssh';
        const role = process.env.VAULT_SSH_ROLE || 'user-login';

        // principal = which local account the cert may log in as (authorization).
        // engineerId = the actual requesting human, wired through as Vault's
        // key_id — deliberately distinct fields. Conflating the two would
        // silently defeat the IEC 62443 SR 6.1 non-repudiation requirement
        // this endpoint exists to satisfy (sshd logs the Key ID on every
        // successful cert login, so this is what makes "who logged in as
        // the shared account, and when" traceable).
        const body = JSON.stringify({
          public_key: publicKey,
          valid_principals: principal,
          key_id: engineerId,
          cert_type: 'user',
          ...(ttl ? { ttl } : {})
        });

        const url = new URL(`/v1/${mount}/sign/${role}`, vaultAddr);
        const vaultReq = https.request(url, {
          method: 'PUT',
          headers: {
            'X-Vault-Token': vaultToken,
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body)
          }
        }, (vaultRes) => {
          let data = '';
          vaultRes.on('data', (chunk) => { data += chunk; });
          vaultRes.on('end', () => {
            let parsed;
            try {
              parsed = JSON.parse(data);
            } catch (e) {
              return reject(new Error(`Vault returned non-JSON response (HTTP ${vaultRes.statusCode}): ${data}`));
            }
            if (vaultRes.statusCode !== 200) {
              const errMsg = (parsed.errors || []).join('; ') || `HTTP ${vaultRes.statusCode}`;
              return reject(new Error(`Vault SSH sign failed: ${errMsg}`));
            }
            if (!parsed.data || !parsed.data.signed_key) {
              return reject(new Error(`Unexpected Vault response: ${data}`));
            }
            resolve(parsed.data.signed_key);
          });
        });
        vaultReq.on('error', reject);
        vaultReq.write(body);
        vaultReq.end();
      });
    }

    app.post('/api/ssh-sign', (req, res) => {
      const apiKey = process.env.SSH_SIGN_API_KEY;
      if (!apiKey) {
        console.error('[ssh-sign] SSH_SIGN_API_KEY not configured — refusing all requests (fail closed)');
        return res.status(503).json({ status: 'error', message: 'ssh-sign endpoint not configured' });
      }
      if (req.get('X-SSH-Sign-Key') !== apiKey) {
        return res.status(401).json({ status: 'error', message: 'unauthorized' });
      }

      const { public_key, principal, engineer_id, ttl } = req.body || {};
      if (!public_key || !principal || !engineer_id) {
        return res.status(400).json({
          status: 'error',
          message: 'Missing required fields: public_key, principal, engineer_id'
        });
      }

      vaultSshSign(public_key, principal, engineer_id, ttl)
        .then((signedKey) => {
          console.log(`[ssh-sign] Issued cert for engineer_id=${engineer_id} principal=${principal}`);
          res.json({ status: 'ok', certificate: signedKey });
        })
        .catch((err) => {
          console.error('[ssh-sign] Vault sign failed:', err.message);
          res.status(502).json({ status: 'error', message: err.message });
        });
    });
    // ────────────────────────────────────────────────────────────────────────

    // ── SELinux AVC Denial Reporting Endpoints ──────────────────────────────
    // DUT posts JSON batches; server merges into a single avc-denials.json per device.

    // POST /api/avc-report  — receive AVC denial batch and merge into single per-device file
    app.post('/api/avc-report', (req, res) => {
      const report = req.body;

      if (!report || !report.device_id) {
        return res.status(400).json({ error: 'Missing required field: device_id' });
      }

      const deviceId   = report.device_id;
      const receivedAt = new Date().toISOString();

      // Lazy-load merged state from disk if not in memory
      if (!avcStore.has(deviceId)) {
        const disk = loadMergedState(deviceId);
        if (disk) {
          avcStore.set(deviceId, disk);
        } else {
          avcStore.set(deviceId, {
            device_id:              deviceId,
            first_upload_timestamp: report.upload_timestamp || receivedAt,
            last_upload_timestamp:  null,
            last_received_at:       null,
            upload_count:           0,
            total_raw_denials:      0,
            denialMap:              new Map()
          });
        }
      }

      const merged = avcStore.get(deviceId);
      const incomingDenials = report.denials || [];
      let newTypes = 0;

      for (const d of incomingDenials) {
        const key = denialKey(d);
        if (merged.denialMap.has(key)) {
          const existing = merged.denialMap.get(key);
          existing.occurrence_count = (existing.occurrence_count || 1) + (d.occurrence_count || 1);
          if (d.first_seen && (!existing.first_seen || d.first_seen < existing.first_seen))
            existing.first_seen = d.first_seen;
          if (d.last_seen && (!existing.last_seen || d.last_seen > existing.last_seen))
            existing.last_seen = d.last_seen;
        } else {
          merged.denialMap.set(key, { ...d });
          newTypes++;
        }
      }

      // Accumulate counters and refresh metadata from this upload
      merged.upload_count    = (merged.upload_count || 0) + 1;
      merged.total_raw_denials = (merged.total_raw_denials || 0) + (report.raw_denial_count || 0);
      merged.last_upload_timestamp = report.upload_timestamp || receivedAt;
      merged.last_received_at      = receivedAt;
      merged.firmware_version      = report.firmware_version;
      merged.fw_build              = report.fw_build;
      merged.selinux_policy_version = report.selinux_policy_version;
      merged.wnc_local_version     = report.wnc_local_version;
      merged.wnc_local_te_lines    = report.wnc_local_te_lines;
      merged.wnc_local_fc_lines    = report.wnc_local_fc_lines;
      merged.selinux_mode          = report.selinux_mode;

      let savedState = null;
      try {
        savedState = saveMergedState(merged);
        console.log(`[AVC] ${deviceId}: +${incomingDenials.length} incoming (+${newTypes} new) ` +
                    `→ ${merged.denialMap.size} total unique types (upload #${merged.upload_count})`);
      } catch (e) {
        console.error('[AVC] Failed to persist merged state:', e.message);
      }

      res.json({
        status:                'ok',
        incoming_unique_types: incomingDenials.length,
        new_types_added:       newTypes,
        total_unique_types:    merged.denialMap.size,
        upload_count:          merged.upload_count
      });
    });

    // GET /api/avc-report/:deviceId  — return merged denial set for a device
    app.get('/api/avc-report/:deviceId', (req, res) => {
      const deviceId = req.params.deviceId;
      let merged = avcStore.get(deviceId);
      if (!merged) {
        const disk = loadMergedState(deviceId);
        if (!disk) return res.json({ device_id: deviceId, upload_count: 0, denials: [] });
        avcStore.set(deviceId, disk);
        merged = disk;
      }
      const denials = Array.from(merged.denialMap.values())
        .sort((a, b) => (b.occurrence_count || 0) - (a.occurrence_count || 0));
      res.json({
        device_id:                 merged.device_id,
        first_upload_timestamp:    merged.first_upload_timestamp,
        last_upload_timestamp:     merged.last_upload_timestamp,
        last_received_at:          merged.last_received_at,
        upload_count:              merged.upload_count,
        total_raw_denials:         merged.total_raw_denials,
        total_unique_denial_types: denials.length,
        firmware_version:          merged.firmware_version,
        selinux_policy_version:    merged.selinux_policy_version,
        wnc_local_version:         merged.wnc_local_version,
        selinux_mode:              merged.selinux_mode,
        denials
      });
    });

    // GET /api/avc-report  — summary of all devices with AVC data
    app.get('/api/avc-report', (req, res) => {
      // Scan disk so we surface devices that exist on disk but not yet in avcStore
      const onDisk = fs.existsSync(AVC_DIR)
        ? fs.readdirSync(AVC_DIR)
            .filter(d => d !== 'backup' && fs.existsSync(path.join(AVC_DIR, d, MERGED_FILENAME)))
        : [];
      const summary = onDisk.map(deviceId => {
        try {
          const data = JSON.parse(fs.readFileSync(path.join(AVC_DIR, deviceId, MERGED_FILENAME), 'utf8'));
          return {
            device_id:                 deviceId,
            upload_count:              data.upload_count,
            last_upload_timestamp:     data.last_upload_timestamp,
            last_received_at:          data.last_received_at,
            total_unique_denial_types: data.total_unique_denial_types,
            total_raw_denials:         data.total_raw_denials,
            selinux_mode:              data.selinux_mode,
            selinux_policy_version:    data.selinux_policy_version,
            firmware_version:          data.firmware_version
          };
        } catch (_) {
          return { device_id: deviceId };
        }
      });
      res.json({ total_devices: summary.length, devices: summary });
    });

    // GET /api/avc-files  — list each device's single merged file
    app.get('/api/avc-files', (req, res) => {
      try {
        const devices = fs.existsSync(AVC_DIR)
          ? fs.readdirSync(AVC_DIR).filter(d => d !== 'backup' && fs.statSync(path.join(AVC_DIR, d)).isDirectory())
          : [];
        const summary = devices.map(deviceId => {
          const filePath = path.join(AVC_DIR, deviceId, MERGED_FILENAME);
          if (!fs.existsSync(filePath)) return { device_id: deviceId, file: null };
          try {
            const stat = fs.statSync(filePath);
            const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            return {
              device_id:                 deviceId,
              file:                      MERGED_FILENAME,
              size_bytes:                stat.size,
              upload_count:              data.upload_count,
              last_upload_timestamp:     data.last_upload_timestamp,
              total_unique_denial_types: data.total_unique_denial_types,
              selinux_mode:              data.selinux_mode,
              selinux_policy_version:    data.selinux_policy_version,
              wnc_local_version:         data.wnc_local_version,
              firmware_version:          data.firmware_version
            };
          } catch (_) {
            return { device_id: deviceId, file: MERGED_FILENAME };
          }
        });
        res.json({ total_devices: summary.length, devices: summary });
      } catch (e) {
        res.status(500).json({ error: e.message });
      }
    });

    // GET /api/avc-files/:deviceId  — metadata for the single merged file of a device
    app.get('/api/avc-files/:deviceId', (req, res) => {
      const deviceId = req.params.deviceId;
      const filePath = path.join(AVC_DIR, deviceId, MERGED_FILENAME);
      if (!fs.existsSync(filePath)) {
        return res.json({ device_id: deviceId, file: null });
      }
      try {
        const stat = fs.statSync(filePath);
        const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
        res.json({
          device_id:                 deviceId,
          file:                      MERGED_FILENAME,
          size_bytes:                stat.size,
          upload_count:              data.upload_count,
          first_upload_timestamp:    data.first_upload_timestamp,
          last_upload_timestamp:     data.last_upload_timestamp,
          last_received_at:          data.last_received_at,
          total_unique_denial_types: data.total_unique_denial_types,
          total_raw_denials:         data.total_raw_denials,
          selinux_mode:              data.selinux_mode,
          selinux_policy_version:    data.selinux_policy_version,
          wnc_local_version:         data.wnc_local_version,
          firmware_version:          data.firmware_version
        });
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
    // GET /api/avc-download  — single combined file with all devices' merged AVC denials.
    // After sending the response the originals are moved to avc-reports/backup/<timestamp>/
    // and cleared from the in-memory cache so the next upload cycle starts fresh.
    app.get('/api/avc-download', (req, res) => {
      try {
        const devices = fs.existsSync(AVC_DIR)
          ? fs.readdirSync(AVC_DIR).filter(d => d !== 'backup' && fs.statSync(path.join(AVC_DIR, d)).isDirectory())
          : [];

        const combined = {
          generated_at: new Date().toISOString(),
          total_devices: 0,
          total_unique_denial_types: 0,
          total_raw_denials: 0,
          devices: []
        };

        // Collect which files were successfully read so we know what to back up
        const toBackup = [];
        for (const deviceId of devices) {
          const filePath = path.join(AVC_DIR, deviceId, MERGED_FILENAME);
          if (!fs.existsSync(filePath)) continue;
          try {
            const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
            combined.devices.push(data);
            combined.total_unique_denial_types += data.total_unique_denial_types || 0;
            combined.total_raw_denials         += data.total_raw_denials || 0;
            toBackup.push({ deviceId, filePath });
          } catch (_) {}
        }
        combined.total_devices = combined.devices.length;

        const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);

        // After the response is fully sent: move originals to backup/, clear cache
        res.on('finish', () => {
          if (toBackup.length === 0) return;
          const backupDir = path.join(AVC_DIR, 'backup', ts);
          try {
            fs.mkdirSync(backupDir, { recursive: true });
            for (const { deviceId, filePath } of toBackup) {
              const destDir = path.join(backupDir, deviceId);
              fs.mkdirSync(destDir, { recursive: true });
              fs.renameSync(filePath, path.join(destDir, MERGED_FILENAME));
              avcStore.delete(deviceId);
            }
            console.log(`[AVC] download: ${toBackup.length} file(s) moved to backup/${ts}/`);
          } catch (e) {
            console.error('[AVC] backup after download failed:', e.message);
          }
        });

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="avc-denials-combined-${ts}.json"`);
        res.json(combined);
      } catch (e) {
        console.error('[AVC] avc-download failed:', e.message);
        res.status(500).json({ error: e.message });
      }
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
