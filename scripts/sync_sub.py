import base64
import json
import os
import sys
import urllib.parse
import urllib.request
import yaml

# Берём ссылку из Secrets GitHub Actions или переменной окружения
SOURCE_URL = os.environ.get("SUB_SOURCE_URL")

if not SOURCE_URL:
  print("Ошибка: Переменная SUB_SOURCE_URL не задана!")
  sys.exit(1)


def fetch_and_convert():
  print(f"Загрузка подписки...")
  req = urllib.request.Request(
      SOURCE_URL,
      headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
  )
  with urllib.request.urlopen(req, timeout=30) as resp:
    raw = resp.read().decode("utf-8")
    data = json.loads(raw)

  links = []
  clash_proxies = []

  for item in data:
    remarks = item.get("remarks", "").strip()
    if "Автовыбор" in remarks:
      continue

    for ob in item.get("outbounds", []):
      proto = ob.get("protocol")
      stream = ob.get("streamSettings", {})
      network = stream.get("network", "tcp")
      security = stream.get("security", "none")
      tag = remarks or ob.get("tag", "proxy")
      tag_encoded = urllib.parse.quote(tag)

      # Конвертация VLESS
      if proto == "vless":
        vnext = ob["settings"]["vnext"][0]
        addr = vnext["address"]
        port = vnext["port"]
        user = vnext["users"][0]
        uuid = user["id"]
        flow = user.get("flow", "")

        params = {"type": network}
        if security:
          params["security"] = security
        if flow:
          params["flow"] = flow

        if security == "reality":
          rs = stream.get("realitySettings", {})
          if rs.get("serverName"):
            params["sni"] = rs["serverName"]
          if rs.get("fingerprint"):
            params["fp"] = rs["fingerprint"]
          if rs.get("publicKey"):
            params["pbk"] = rs["publicKey"]
          if rs.get("shortId"):
            params["sid"] = rs["shortId"]
          if rs.get("spiderX"):
            params["spx"] = rs["spiderX"]
        elif security == "tls":
          ts = stream.get("tlsSettings", {})
          if ts.get("serverName"):
            params["sni"] = ts["serverName"]
          if ts.get("fingerprint"):
            params["fp"] = ts["fingerprint"]
          if ts.get("alpn"):
            params["alpn"] = ",".join(ts["alpn"])

        if network == "ws":
          ws = stream.get("wsSettings", {})
          if ws.get("path"):
            params["path"] = ws["path"]
          if ws.get("headers", {}).get("Host"):
            params["host"] = ws["headers"]["Host"]
        elif network == "grpc":
          gs = stream.get("grpcSettings", {})
          if gs.get("serviceName"):
            params["serviceName"] = gs["serviceName"]
        elif network in ("xhttp", "httpupgrade"):
          xs = stream.get("xhttpSettings", {}) or stream.get(
              "httpupgradeSettings", {}
          )
          if xs.get("path"):
            params["path"] = xs["path"]
          if xs.get("host"):
            params["host"] = xs["host"]

        query = urllib.parse.urlencode(params)
        links.append(f"vless://{uuid}@{addr}:{port}?{query}#{tag_encoded}")

        # Для Clash
        cp = {
            "name": tag,
            "type": "vless",
            "server": addr,
            "port": port,
            "uuid": uuid,
            "udp": True,
            "network": network,
        }
        if flow:
          cp["flow"] = flow
        if security == "reality":
          rs = stream.get("realitySettings", {})
          cp["tls"] = True
          cp["reality-opts"] = {
              "public-key": rs.get("publicKey", ""),
              "short-id": rs.get("shortId", ""),
          }
          if rs.get("serverName"):
            cp["servername"] = rs["serverName"]
          if rs.get("fingerprint"):
            cp["client-fingerprint"] = rs["fingerprint"]
        clash_proxies.append(cp)

      # Конвертация Hysteria 2
      elif proto == "hysteria":
        sett = ob.get("settings", {})
        hs = stream.get("hysteriaSettings", {})
        ts = stream.get("tlsSettings", {})
        addr = sett.get("address")
        port = sett.get("port")
        auth = hs.get("auth")
        sni = ts.get("serverName", "")
        alpn = ",".join(ts.get("alpn", ["h3"]))
        insecure = 1 if ts.get("allowInsecure") else 0
        links.append(
            f"hysteria2://{auth}@{addr}:{port}/?sni={sni}&alpn={alpn}&insecure={insecure}#{tag_encoded}"
        )

        clash_proxies.append({
            "name": tag,
            "type": "hysteria2",
            "server": addr,
            "port": port,
            "password": auth,
            "sni": sni,
            "skip-cert-verify": bool(ts.get("allowInsecure")),
            "alpn": ts.get("alpn", ["h3"]),
        })

      # Конвертация Shadowsocks
      elif proto == "shadowsocks":
        srv = ob["settings"]["servers"][0]
        method = srv["method"]
        pwd = srv["password"]
        addr = srv["address"]
        port = srv["port"]
        userinfo = base64.b64encode(f"{method}:{pwd}".encode()).decode()
        links.append(f"ss://{userinfo}@{addr}:{port}#{tag_encoded}")
        clash_proxies.append({
            "name": tag,
            "type": "ss",
            "server": addr,
            "port": port,
            "cipher": method,
            "password": pwd,
            "udp": True,
        })

  print(f"Успешно обработано узлов: {len(links)}")

  out_dir = os.path.join(
      os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sub"
  )
  os.makedirs(out_dir, exist_ok=True)

  # Сохраняем текстовый список под Karing
  header = [
      "#profile-title: My VPN",
      "#profile-update-interval: 1",
      "",
  ]
  with open(os.path.join(out_dir, "karing.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(header + links))

  # Сохраняем Clash YAML
  proxy_names = [p["name"] for p in clash_proxies]
  clash_config = {
      "port": 7890,
      "mode": "rule",
      "proxies": clash_proxies,
      "proxy-groups": [
          {
              "name": "⚡ AUTO",
              "type": "url-test",
              "url": "https://cp.cloudflare.com/generate_204",
              "interval": 300,
              "proxies": proxy_names,
          },
          {
              "name": "SELECT",
              "type": "select",
              "proxies": ["⚡ AUTO"] + proxy_names,
          },
      ],
      "rules": ["MATCH,SELECT"],
  }
  with open(os.path.join(out_dir, "clash.yaml"), "w", encoding="utf-8") as f:
    yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)


if __name__ == "__main__":
  fetch_and_convert()
