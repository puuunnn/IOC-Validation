import requests
import json
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Konfigurasi Elasticsearch dan Webhook ===
ELASTIC_URL = "https://localhost:9200/logs-*/_search"
ELASTIC_USER = "dimas.wahyudi@nindyakarya.co.id"  # Isi jika pakai basic auth
ELASTIC_PASS = "UbayAqila#07"
SHUFFLE_WEBHOOK = "https://10.14.0.95:3443/api/v1/hooks/webhook_094e4e8f-f3a1-4cae-b9b3-9e4acfa984b1"

# === Query OSSEC dengan waktu dinamis ===
query = {
    "size": 0,
    "query": {
        "bool": {
            "filter": [
                {"term": {"event.module": "ossec"}},
                {"term": {"event.dataset": "alert"}},
                {
                    "range": {
                        "@timestamp": {
                            "gte": "now-10d/d",
                            "lte": "now"
                        }
                    }
                }
            ]
        }
    },
    "aggs": {
        "rules": {
            "terms": {"field": "rule.name", "size": 100},
            "aggs": {
                "categories": {
                    "terms": {"field": "rule.category.keyword", "size": 100},
                    "aggs": {
                        "timestamps": {
                            "terms": {"field": "@timestamp", "size": 100, "order": {"_key": "desc"}},
                            "aggs": {
                                "sources": {
                                    "terms": {"field": "source.ip", "size": 100},
                                    "aggs": {
                                        "agents": {
                                            "terms": {"field": "agent.ip", "size": 100},
                                            "aggs": {
                                                "agent_names": {
                                                    "terms": {"field": "agent.name", "size": 100},
                                                    "aggs": {
                                                        "severities": {
                                                            "terms": {"field": "event.severity_label.keyword", "size": 100},
                                                            "aggs": {
                                                                "countries": {
                                                                    "terms": {"field": "source.geo.country_name.keyword", "size": 100},
                                                                    "aggs": {
                                                                        "modules": {
                                                                            "terms": {"field": "event.module", "size": 100}
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
        }
    }
}

# === Fungsi parsing alert ===
def extract_alerts(aggs):
    alerts = []
    for rule in aggs.get("aggregations", {}).get("rules", {}).get("buckets", []):
        rule_name = rule.get("key")
        for cat in rule.get("categories", {}).get("buckets", []):
            category = cat.get("key")
            for ts in cat.get("timestamps", {}).get("buckets", []):
                timestamp = ts.get("key_as_string", "")
                for src in ts.get("sources", {}).get("buckets", []):
                    src_ip = src.get("key")
                    for agent in src.get("agents", {}).get("buckets", []):
                        dst_ip = agent.get("key")
                        for agname in agent.get("agent_names", {}).get("buckets", []):
                            agent_name = agname.get("key")
                            for sev in agname.get("severities", {}).get("buckets", []):
                                severity = sev.get("key")
                                for cty in sev.get("countries", {}).get("buckets", []):
                                    country = cty.get("key")
                                    for mod in cty.get("modules", {}).get("buckets", []):
                                        module = mod.get("key")
                                        alerts.append({
                                            "rule": rule_name,
                                            "category": category,
                                            "timestamp": timestamp,
                                            "source_ip": src_ip,
                                            "destination_ip": dst_ip,
                                            "agent_name": agent_name,
                                            "severity": severity,
                                            "country": country,
                                            "module": module
                                        })
    return alerts

# === Kirim ke Elasticsearch ===
resp = requests.post(
    ELASTIC_URL,
    json=query,
    auth=HTTPBasicAuth(ELASTIC_USER, ELASTIC_PASS),
    verify=False
)

# === Kirim hasil ke webhook Shuffle ===
if resp.status_code == 200:
    hasil = resp.json()
    alerts = extract_alerts(hasil)
    print(f"[INFO] Total alert dikirim: {len(alerts)}")

    if alerts:
        post = requests.post(SHUFFLE_WEBHOOK, json={"alerts": alerts}, verify=False)
        if post.status_code == 200:
            print("✅ Berhasil dikirim ke Shuffle")
        else:
            print(f"❌ Gagal kirim ke Shuffle: {post.status_code} - {post.text}")
    else:
        print("⚠️ Tidak ada data alert yang ditemukan dalam rentang waktu")
else:
    print(f"❌ Gagal query Elasticsearch: {resp.status_code}")
    print(resp.text)