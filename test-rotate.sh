curl -X POST http://34.80.129.102:3000/api/rotate/kms-ec4fe014089a \
  -H "Content-Type: application/json" \
  -d '{
    "service": "mqtt",
    "cn": "mqtt.csyang.org",
    "san_dns": [
      "mqtt.csyang.org"
    ]
  }'
