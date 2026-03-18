import argparse
import json
import threading
import time
import random
import requests

def gen_features():
    feats = [0.0]*52
    feats[0] = random.uniform(0, 1)
    feats[10] = random.uniform(1000, 100000)
    feats[11] = random.uniform(10, 1000)
    feats[41] = random.uniform(1000, 65535)
    feats[43] = random.randint(0, 20)
    return feats

def call_ids(ids_url, feats):
    try:
        r = requests.post(ids_url, json={"features":feats}, timeout=2)
        return r.json()
    except Exception:
        return {"class":"Benign","confidence":1.0}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--ids", default="http://127.0.0.1:5000/predict")
    p.add_argument("--agent", default="http://127.0.0.1:8080")
    p.add_argument("--token", default="")
    p.add_argument("--duration", type=int, default=10)
    p.add_argument("--threshold", type=float, default=0.98)
    p.add_argument("--class", dest="klass", default="DDOS attack-HOIC")
    p.add_argument("--min_evidence", type=int, default=2)
    args = p.parse_args()
    headers = {}
    if args.token:
        headers["Authorization"] = "Bearer "+args.token
    end = time.time() + args.duration
    evidence = {}
    blocks = 0
    preds = 0
    while time.time() < end:
        feats = gen_features()
        pred = call_ids(args.ids, feats)
        preds += 1
        if pred.get("class") == args.klass and pred.get("confidence",0) >= args.threshold:
            src_ip = "10.1.2.3"
            evidence[src_ip] = evidence.get(src_ip,0) + 1
            if evidence[src_ip] >= args.min_evidence:
                try:
                    r = requests.get(args.agent+"/block", params={"ip":src_ip,"ttl":"300"}, headers=headers, timeout=2)
                    if r.status_code == 200:
                        blocks += 1
                    evidence[src_ip] = 0
                except Exception:
                    pass
        time.sleep(0.1)
    try:
        r = requests.get(args.agent+"/stats", headers=headers, timeout=2)
        stats = r.json()
    except Exception:
        stats = {}
    print(json.dumps({"predictions":preds,"blocks_attempted":blocks,"agent_stats":stats}))

if __name__ == "__main__":
    main()
