import requests
from requests.auth import HTTPBasicAuth
import urllib3
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === KONFIGURASI ===
ELASTIC_URL = "https://localhost:9200/logs-*/_search"
ELASTIC_USER = "dimas.wahyudi@nindyakarya.co.id"
ELASTIC_PASS = "Aqila#03"
SHUFFLE_WEBHOOK = "https://10.14.0.95:3443/api/v1/hooks/webhook_094e4e8f-f3a1-4cae-b9b3-9e4acfa984b1"

# === QUERY AGGREGASI DINAMIS ===
query = {
    "size": 0,
    "query": {
        "range": {
            "@timestamp": {
                "gte": "now/d",
                "lte": "now"
            }
        }
    },
    "aggs": {
        "rules": {
            "terms": {
                "field": "rule.name",
                "order": { "_count": "desc" },
                "size": 200
            },
            "aggs": {
                "timestamps": {
                    "terms": {
                        "field": "@timestamp",
                        "order": { "_count": "desc" },
                        "size": 200
                    },
                    "aggs": {
                        "source_ips": {
                            "terms": {
                                "field": "source.ip",
                                "order": { "_count": "desc" },
                                "size": 200
                            },
                            "aggs": {
                                "destination_ips": {
                                    "terms": {
                                        "field": "destination.ip",
                                        "order": { "_count": "desc" },
                                        "size": 200
                                    },
                                    "aggs": {
                                        "severity": {
                                            "terms": {
                                                "field": "event.severity_label",
                                                "order": { "_count": "desc" },
                                                "size": 200
                                            },
                                            "aggs": {
                                                "countries": {
                                                    "terms": {
                                                        "field": "source.geo.country_name",
                                                        "order": { "_count": "desc" },
                                                        "size": 200
                                                    },
                                                    "aggs": {
                                                        "modules": {
                                                            "terms": {
                                                                "field": "event.module",
                                                                "order": { "_count": "desc" },
                                                                "size": 200
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

# === PARSE HASIL AGGREGASI ===
def extract_alerts(aggs):
    alerts = []
    rules = aggs.get("aggregations", {}).get("rules", {}).get("buckets", [])
    for rule in rules:
        rule_name = rule.get("key")
        timestamps = rule.get("timestamps", {}).get("buckets", [])
        for ts in timestamps:
            timestamp = ts.get("key_as_string")
            srcs = ts.get("source_ips", {}).get("buckets", [])
            for src in srcs:
                src_ip = src.get("key")
                dsts = src.get("destination_ips", {}).get("buckets", [])
                for dst in dsts:
                    dst_ip = dst.get("key")
                    severities = dst.get("severity", {}).get("buckets", [])
                    for sev in severities:
                        severity = sev.get("key")
                        countries = sev.get("countries", {}).get("buckets", [])
                        for cty in countries:
                            country = cty.get("key")
                            modules = cty.get("modules", {}).get("buckets", [])
                            for mod in modules:
                                module = mod.get("key")
                                alerts.append({
                                    "rule": rule_name,
                                    "timestamp": timestamp,
                                    "source_ip": src_ip,
                                    "destination_ip": dst_ip,
                                    "severity": severity,
                                    "country": country,
                                    "module": module
                                })
    return alerts

# === KIRIM QUERY KE ELASTICSEARCH ===
response = requests.post(
    ELASTIC_URL,
    json=query,
    auth=HTTPBasicAuth(ELASTIC_USER, ELASTIC_PASS),
    verify=False
)

# === KIRIM SEMUA HASIL SEKALIGUS KE SHUFFLE ===
if response.status_code == 200:
    hasil = response.json()
    alert_list = extract_alerts(hasil)

    print(f"[INFO] Total alert terkumpul: {len(alert_list)}")
    print("[INFO] Mengirim seluruh data alert sebagai satu payload ke webhook...")

    # Kirim semuanya sekaligus
    r = requests.post(
        SHUFFLE_WEBHOOK,
        json={"alerts": alert_list},
        verify=False
    )

    if r.status_code == 200:
        print("✅ Seluruh data alert berhasil dikirim ke Shuffle!")
    else:
        print(f"❌ Gagal kirim ke Shuffle: {r.status_code} - {r.text}")

else:
    print(f"❌ Gagal mengambil data dari Elasticsearch: {response.status_code}")
    print(response.text)