import html
import json
import re
import time
import urllib.error
import urllib.request

# @BotFather-dən aldığınız tokeni dırnaqların içinə yazın:
BOT_TOKEN = "8656923585:AAFcWyLIddnFHJd5WJ_CUnKdhiYv5vXiGOY"
AZSHIELD_API = "http://127.0.0.1:8000"


def tg_request(method: str, payload: dict) -> dict:
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def scan_with_azshield(user_text: str) -> dict:
    clean = user_text.strip()
    is_only_url = bool(re.fullmatch(r"(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[^\s]*)?", clean))

    if is_only_url:
        endpoint = f"{AZSHIELD_API}/api/scan-url"
        body = {"url": clean, "online_osint": False}
    else:
        endpoint = f"{AZSHIELD_API}/api/scan-text"
        body = {"text": clean}

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode("utf-8"))


def format_reply(res: dict) -> str:
    score = res.get("score", 0)
    level = html.escape(str(res.get("level", "NAMƏLUM")))
    target = html.escape(str(res.get("target", "")))
    latency = res.get("latency_ms", 0)
    rules = res.get("rules", [])

    if score >= 60:
        header = "🚨 <b>TƏHLÜKƏ AŞKARLANDI — BLOKLANMALIDIR!</b>"
    elif score >= 35:
        header = "⚠️ <b>ŞÜBHƏLİ LİNK / MESAJ — DİQQƏTLİ OLUN!</b>"
    else:
        header = "✅ <b>TƏHLÜKƏSİZ / TƏMİZ</b>"

    rules_lines = "\n".join(
        f"• <code>{html.escape(r.get('id', ''))}</code>: {html.escape(r.get('category', ''))} (+{r.get('weight', 0)})"
        for r in rules[:4]
    )

    return (
        f"{header}\n\n"
        f"🎯 <b>Hədəf:</b> <code>{target}</code>\n"
        f"📊 <b>Risk Balı:</b> <b>{score}%</b> ({level})\n"
        f"⚡ <b>Analiz Müddəti:</b> {latency} ms (Local-First)\n\n"
        f"🔍 <b>Texniki Sübutlar:</b>\n{rules_lines}"
    )


def main():
    if "BURAYA_BOTFATHER" in BOT_TOKEN:
        print("[XƏTA] Əvvəlcə telegram_bot.py faylında BOT_TOKEN dəyişənini doldurun!")
        return

    print("[AZSHIELD-TG] Telegram SOC Bot körpüsü aktivdir. Mesajlar gözlənilir...")
    offset = 0

    while True:
        try:
            updates = tg_request("getUpdates", {"offset": offset, "timeout": 10})
            for upd in updates.get("result", []):
                offset = upd["update_id"] + 1
                msg = upd.get("message") or upd.get("edited_message")
                if not msg:
                    continue

                chat_id = msg["chat"]["id"]
                text = msg.get("text") or msg.get("caption") or ""
                if not text:
                    continue

                if text.startswith("/start"):
                    tg_request("sendMessage", {
                        "chat_id": chat_id,
                        "parse_mode": "HTML",
                        "text": "🛡️ <b>AzShield IQ SOC Bot</b> aktivdir.\nŞübhəli SMS-i buraya yönləndirin (Forward) və ya link göndərin:"
                    })
                    continue

                result = scan_with_azshield(text)
                tg_request("sendMessage", {
                    "chat_id": chat_id,
                    "parse_mode": "HTML",
                    "text": format_reply(result),
                })
        except urllib.error.URLError:
            print("[XƏBƏRDARLIQ] AzShield serveri (127.0.0.1:8000) və ya şəbəkə cavab vermir...")
            time.sleep(2)
        except Exception as exc:
            print(f"[INFO] Gözlənilməz xəta: {exc}")
            time.sleep(2)


if __name__ == "__main__":
    main()