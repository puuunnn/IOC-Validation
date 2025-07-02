import requests
import json
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === Konfigurasi ===
ELASTIC_URL = "https://localhost:9200/logs-*/_search"
ELASTIC_USER = "dimas.wahyudi@nindyakarya.co.id"  # Isi jika pakai basic auth
ELASTIC_PASS = "UbayAqila#07"
SHUFFLE_WEBHOOK = "https://10.14.0.95:3443/api/v1/hooks/webhook_094e4e8f-f3a1-4cae-b9b3-9e4acfa984b1"

# === Query baru (tanpa rule.category) ===
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
        "5": {
            "terms": {
                "field": "rule.name",
                "order": { "_count": "desc" },
                "size": 100
            },
            "aggs": {
                "6": {
                    "terms": {
                        "field": "@timestamp",
                        "order": { "_count": "desc" },
                        "size": 100
                    },
                    "aggs": {
                        "4": {
                            "terms": {
                                "field": "source.ip",
                                "order": { "_count": "desc" },
                                "size": 100
                            },
                            "aggs": {
                                "2": {
                                    "terms": {
                                        "field": "agent.ip",
                                        "order": { "_count": "desc" },
                                        "size": 100
                                    },
                                    "aggs": {
                                        "3": {
                                            "terms": {
                                                "field": "agent.name",
                                                "order": { "_count": "desc" },
                                                "size": 100
                                            },
                                            "aggs": {
                                                "9": {
                                                    "terms": {
                                                        "field": "event.severity_label.keyword",
                                                        "order": { "_count": "desc" },
                                                        "size": 100
                                                    },
                                                    "aggs": {
                                                        "7": {
                                                            "terms": {
                                                                "field": "source.geo.country_name.keyword",
                                                                "order": { "_count": "desc" },
                                                                "size": 100
                                                            },
                                                            "aggs": {
                                                                "8": {
                                                                    "terms": {
                                                                        "field": "event.module",
                                                                        "order": { "_count": "desc" },
                                                                        "size": 100
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





# === Parser alert ===
def extract_alerts(aggs):
    alerts = []
    rules = aggs.get("aggregations", {}).get("5", {}).get("buckets", [])
    for rule in rules:
        rule_name = rule.get("key")
        timestamps = rule.get("6", {}).get("buckets", [])
        for ts in timestamps:
            timestamp = ts.get("key_as_string")
            srcs = ts.get("4", {}).get("buckets", [])
            for src in srcs:
                src_ip = src.get("key")
                dsts = src.get("2", {}).get("buckets", [])
                for dst in dsts:
                    dst_ip = dst.get("key")
                    agent_names = dst.get("3", {}).get("buckets", [])
                    for agent in agent_names:
                        agent_name = agent.get("key")
                        severities = agent.get("9", {}).get("buckets", [])
                        for sev in severities:
                            severity = sev.get("key")
                            countries = sev.get("7", {}).get("buckets", [])
                            for cty in countries:
                                country = cty.get("key")
                                modules = cty.get("8", {}).get("buckets", [])
                                for mod in modules:
                                    module = mod.get("key")
                                    alerts.append({
                                        "rule": rule_name,
                                        "timestamp": timestamp,
                                        "source_ip": src_ip,
                                        "destination_ip": dst_ip,
                                        "agent_name": agent_name,
                                        "severity": severity,
                                        "country": country,
                                        "module": module
                                    })
    return alerts


# === Eksekusi dan kirim ke webhook ===
resp = requests.post(
    ELASTIC_URL,
    json=query,
    auth=HTTPBasicAuth(ELASTIC_USER, ELASTIC_PASS),
    verify=False
)

if resp.status_code == 200:
    hasil = resp.json()
    alerts = extract_alerts(hasil)
    print(f"[INFO] Total alert dikirim: {len(alerts)}")

    if alerts:
        r = requests.post(SHUFFLE_WEBHOOK, json={"alerts": alerts}, verify=False)
        if r.status_code == 200:
            print("✅ Berhasil kirim ke Shuffle")
        else:
            print(f"❌ Gagal kirim ke Shuffle: {r.status_code} - {r.text}")
    else:
        print("⚠️ Tidak ada alert ditemukan dalam range waktu")
else:
    print(f"❌ Gagal query Elasticsearch: {resp.status_code}")
    print(resp.text)