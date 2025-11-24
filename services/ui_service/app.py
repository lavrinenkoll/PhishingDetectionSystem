import os
import textwrap
import requests
import streamlit as st
import json
import re
import html as html_lib
from deep_translator import GoogleTranslator


COLORS = {
    "safe": "#4CAF50",
    "probable_safe": "#ffec1c",
    "probable_unsafe": "#e86915",
    "unsafe": "#F44336",
}

THRESHOLD_DOM_CHANGE=os.getenv("THRESHOLD_DOM_CHANGE", 50.0)


st.set_page_config(page_title="Phishing Detector", layout="wide")
st.title("Система автоматичного виявлення фішингових сайтів")

url = st.text_input("Введіть URL для перевірки:")

start_button = st.button("Перевірити")

RISK_AGGREGATOR_HOST = os.getenv("RISK_AGGREGATOR_CONTAINER_NAME", "localhost")
RISK_AGGREGATOR_PORT = os.getenv("RISK_AGGREGATOR_PORT", "8000")
RISK_AGGREGATOR_URL = f"http://{RISK_AGGREGATOR_HOST}:{RISK_AGGREGATOR_PORT}/check"
RISK_AGGREGATOR_SCORE_URL = f"http://{RISK_AGGREGATOR_HOST}:{RISK_AGGREGATOR_PORT}/score"


def safe_error_text(err, max_len=500):
    if not err:
        return ""

    text = str(err)
    if len(text) > max_len:
        text = text[:max_len] + "… (обрізано)"

    text = text.replace("\r", " ").replace("\n", " ")
    text = html_lib.escape(text)

    return text


def render_threat_intel(result):
    data = result["data"]
    if data.get("error", None):
        css = f"""
                <style>
                  .card-threat-error {{
                    border: 6px solid {COLORS.get("unsafe", "#F44336")};
                    border-radius: 10px;
                    padding: 10px 14px;
                    margin: 6px 0 10px 0;
                    font-family: 'Inter', sans-serif;
                  }}
                  .card-threat-error h3 {{
                    margin: 0; padding: 0; line-height: 1.15;
                  }}
                  .msg {{
                    margin-top:8px; font-size:14px; color:#C62828; font-weight:600;
                  }}
                  small {{ color:#888; }}
                </style>
                """

        html_block = f"""
        {css}
        <div class="card-threat-error">
            <h3>🔍 Перевірка у базах відкритих загроз</h3>
            <div class="sp"></div>
            <p class="msg">❌ Помилка при отриманні даних з сервісу перевірки загроз: <strong>{safe_error_text(data.get("error"))}</strong>
        </div>
        """
        return html_block

    url = data["url"]
    vt = data["virustotal"]
    wr = data["webrisk"]

    vt_stats = vt.get("stats", {}) or {}

    harmless   = int(vt_stats.get("harmless", 0))
    suspicious = int(vt_stats.get("suspicious", 0))
    malicious  = int(vt_stats.get("malicious", 0))
    undetected = int(vt_stats.get("undetected", 0))
    total = max(harmless + suspicious + malicious + undetected, 1)

    wr_risk = 0 if wr.get("safe") else 1
    vt_risk = (suspicious + malicious) / total if total else 0
    final_risk = 0.5 * wr_risk + 0.5 * vt_risk

    if final_risk < 0.10:
        border = COLORS["safe"]
    elif final_risk < 0.30:
        border = COLORS["probable_safe"]
    elif final_risk < 0.60:
        border = COLORS["probable_unsafe"]
    else:
        border = COLORS["unsafe"]

    if vt_risk < 0.10:
        vt_verdict_text = "✅ Безпечний"
    elif vt_risk < 0.30:
        vt_verdict_text = "⚠️ Скоріше безпечний"
    elif vt_risk < 0.60:
        vt_verdict_text = "⚠️ Скоріше небезпечний"
    else:
        vt_verdict_text = "❌ Небезпечний"

    w_harmless   = 100 * harmless   / total
    w_suspicious = 100 * suspicious / total
    w_malicious  = 100 * malicious  / total
    w_undetected = 100 * undetected / total

    css = f"""
    <style>
      .card1 {{
        border: 6px solid var(--border-color, #000);
        border-radius: 10px;
        padding: 10px 14px;
        margin: 4px 0 6px 0;
        font-family: 'Inter', sans-serif;
      }}

      .sp {{ height: 15px; }}

      .card1 h3, .card1 h4, .card1 p, .card1 small {{
        margin: 0 !important;
        padding: 0 !important;
        line-height: 1.15;
      }}

      .stackbar {{
        display: flex; width: 100%; height: 32px; border-radius: 6px; overflow: hidden;
        border: 1px solid rgba(0,0,0,0.08); margin-top: 4px;
      }}
      .seg {{
        height: 100%; display: flex; align-items: center; justify-content: center;
        font-size: 11px; font-weight: 700; white-space: nowrap;
      }}
      .seg--harmless   {{ background:#4CAF50; color:#fff; }}
      .seg--suspicious {{ background:#FFC107; }}
      .seg--malicious  {{ background:#F44336; color:#fff; }}
      .seg--undetected {{ background:#9E9E9E; }}
      .seg span {{ padding: 0 6px; }}

    </style>
    """

    html = f"""
    {css}
    <div class="card1" style="--border-color: {border}">
      <h3>🔍 Перевірка у базах відкритих загроз</h3>
      
      <div class="sp"></div>
      
      <p><strong>🌐 WebRisk:</strong> {"✅ Безпечний" if wr.get("safe") else "❌ Небезпечний"}</p>
      <small>{wr.get("checked_at","")}</small>
      
      <div class="sp"></div>
        
      <p><strong>🧪 VirusTotal:</strong> {vt_verdict_text}</p>
      <p>Підозрілі / всі перевірки: <strong>{suspicious + malicious}</strong> з <strong>{harmless + suspicious + malicious + undetected}</strong></p>

      <div class="stackbar" title="Безпечні / Підозрілі / Небезпечні / Невідомі">
        <div class="seg seg--harmless"   style="width:{w_harmless:.6f}%"><span>{"Безпечні " + str(harmless) if w_harmless>12 else ""}</span></div>
        <div class="seg seg--suspicious" style="width:{w_suspicious:.6f}%"><span>{"Підозрілі " + str(suspicious) if w_suspicious>12 else ""}</span></div>
        <div class="seg seg--malicious"  style="width:{w_malicious:.6f}%"><span>{"Небезпечні " + str(malicious) if w_malicious>12 else ""}</span></div>
        <div class="seg seg--undetected" style="width:{w_undetected:.6f}%"><span>{"Невідомі " + str(undetected) if w_undetected>12 else ""}</span></div>
      </div>

      <div class="sp"></div>
      
      {"<p><a href='" + vt.get("details_url","") + "' target='_blank'>🔗 Повний звіт VirusTotal</a></p>" if vt.get("details_url") else ""}
      <small>{vt.get("checked_at","")}</small>
    </div>
    """

    return html


def render_domain_analyzer(result):
    data = result["data"]

    if data.get("error", None):
        css = f"""
                <style>
                    .card-dom-error {{
                    border: 6px solid {COLORS.get("unsafe", "#F44336")};
                    border-radius: 10px;
                    padding: 10px 14px;
                    margin: 6px 0 10px 0;
                    font-family: 'Inter', sans-serif;
                    }}
                    .card-dom-error h3 {{
                    margin: 0; padding: 0; line-height: 1.15;
                    }}
                    .msg {{
                    margin-top:8px; font-size:14px; color:#C62828; font-weight:600;
                    }}
                    small {{ color:#888; }}
                </style>
                """

        html_block = f"""
        {css}
        <div class="card-dom-error">
            <h3>🌍 Аналіз домену</h3>
            <div class="sp"></div>
            <p class="msg">❌ Помилка при отриманні даних з сервісу аналізу домену: <strong>{safe_error_text(data.get("error"))}</strong>
        </div>
        """
        return html_block

    url = data["url"]
    dom = data["virustotal_domain"]

    stats = dom["stats"]
    harmless   = int(stats.get("harmless", 0))
    suspicious = int(stats.get("suspicious", 0))
    malicious  = int(stats.get("malicious", 0))
    undetected = int(stats.get("undetected", 0))
    total = max(harmless + suspicious + malicious + undetected, 1)

    risk = (suspicious + malicious) / total

    if malicious == 0 and suspicious == 0:
        verdict_text = "✅ Домен виглядає безпечним"
        border = COLORS["safe"]
    elif risk <= 0.2:
        verdict_text = "⚠️ Домен скоріше безпечний"
        border = COLORS["probable_safe"]
    elif risk <= 0.5:
        verdict_text = "⚠️ Домен може бути ризиковим"
        border = COLORS["probable_unsafe"]
    else:
        verdict_text = "❌ Домен має ознаки небезпеки"
        border = COLORS["unsafe"]

    w_harmless   = 100 * harmless   / total
    w_suspicious = 100 * suspicious / total
    w_malicious  = 100 * malicious  / total
    w_undetected = 100 * undetected / total

    css = f"""
    <style>
      .card2 {{
        border: 6px solid var(--border-color, #000);
        border-radius: 10px;
        padding: 10px 14px;
        margin: 4px 0 6px 0;
        font-family: 'Inter', sans-serif;
      }}

      .sp {{ height: 14px; }}

      .card2 h3, .card2 h4, .card2 p, .card2 small {{
        margin: 0 !important;
        padding: 0 !important;
        line-height: 1.15;
      }}

      .stackbar {{
        display: flex; width: 100%; height: 32px; border-radius: 6px; overflow: hidden;
        border: 1px solid rgba(0,0,0,0.08); margin-top: 4px;
      }}
      .seg {{
        height: 100%; display: flex; align-items: center; justify-content: center;
        font-size: 11px; font-weight: 700; white-space: nowrap;
      }}
      .seg--harmless   {{ background:#4CAF50; color:#fff; }}
      .seg--suspicious {{ background:#FFC107; }}
      .seg--malicious  {{ background:#F44336; color:#fff; }}
      .seg--undetected {{ background:#9E9E9E; }}
      .seg span {{ padding: 0 6px; }}
    </style>
    """

    html = f"""
    {css}
    <div class="card2" style="--border-color: {border}">
      <h3>🌍 Аналіз домену</h3>

      <div class="sp"></div>

      <p><strong>Домен:</strong> {dom.get("domain","")}</p>

      <div class="sp"></div>

      <p><strong>🧪 Висновок:</strong> {verdict_text}</p>
      <p>Підозрілих / всі перевірки: <strong>{suspicious + malicious}</strong> з <strong>{total}</strong></p>

      <div class="stackbar" title="Безпечні / Підозрілі / Небезпечні / Невідомі">
        <div class="seg seg--harmless"   style="width:{w_harmless:.6f}%"><span>{"Безпечні " + str(harmless) if w_harmless>12 else ""}</span></div>
        <div class="seg seg--suspicious" style="width:{w_suspicious:.6f}%"><span>{"Підозрілі " + str(suspicious) if w_suspicious>12 else ""}</span></div>
        <div class="seg seg--malicious"  style="width:{w_malicious:.6f}%"><span>{"Небезпечні " + str(malicious) if w_malicious>12 else ""}</span></div>
        <div class="seg seg--undetected" style="width:{w_undetected:.6f}%"><span>{"Невідомі " + str(undetected) if w_undetected>12 else ""}</span></div>
      </div>

      <div class="sp"></div>

      {"<p><a href='" + dom.get("details_url","") + "' target='_blank'>🔗 Повний звіт VirusTotal</a></p>" if dom.get("details_url") else ""}
      <small>{dom.get("last_checked_at","")}</small>
    </div>
    """

    return html


def render_content_analyzer(result):
    data = result["data"]
    if data.get("error", None):
        css = f"""
                <style>
                  .card3-error {{
                    border: 6px solid {COLORS.get("unsafe", "#F44336")};
                    border-radius: 10px;
                    padding: 10px 14px;
                    margin: 6px 0 10px 0;
                    font-family: 'Inter', sans-serif;
                  }}
                  .card3-error h3 {{
                    margin: 0; padding: 0; line-height: 1.15;
                  }}
                  .msg {{
                    margin-top:8px; font-size:14px; color:#C62828; font-weight:600;
                  }}
                  small {{ color:#888; }}
                </style>
                """

        html_block = f"""
        {css}
        <div class="card3-error">
            <h3>📝 Аналіз контенту</h3>
            <div class="sp"></div>
            <p class="msg">❌ Помилка при отриманні даних з сервісу аналізу контенту: <strong>{safe_error_text(data.get("error"))}</strong>
        </div>
        """
        return html_block

    url = result.get("url", "")
    explanation = data.get("explanation", "") or ""
    checked_at = data.get("checked_at", "")
    verdict = bool(data.get("verdict", False))
    screenshot_base64 = data.get("screenshot_base64", None)
    translator = GoogleTranslator(source='en', target='uk')
    try:
        explanation_en = translator.translate(explanation)
    except Exception:
        explanation_en = explanation
    explanation = explanation_en

    if verdict:
        verdict_text = "❌ Контент має ознаки фішингу"
        border = COLORS["unsafe"]
    else:
        verdict_text = "✅ Контент виглядає безпечним"
        border = COLORS["safe"]

    keywords = [
        r"терміново", r"негайно", r"невідкладно", r"обмежений час",
        r"термін дії", r"спливає", r"countdown", r"timer", r"act now",
        r"urgent", r"immediately", r"important notice",

        r"ваш акаунт буде заблоковано", r"заблоковано", r"припинено доступ",
        r"відновіть доступ", r"confirm your identity", r"verify now",
        r"security alert", r"account suspended",

        r"паспорт", r"ID card", r"passport", r"номер паспорту",
        r"ідентифікаційний код", r"ІПН", r"social security number",
        r"особисті дані", r"особисту інформацію", r"personal information",

        r"картка", r"credit card", r"debit card", r"card number",
        r"номер картки", r"bank account", r"рахунок", r"iban",
        r"CVV", r"CVC", r"expiry", r"expiration date",
        r"сплатіть", r"оплата", r"payment", r"pay now", r"invoice",

        r"логін", r"пароль", r"password", r"login details",
        r"one time code", r"одноразовий код", r"SMS-код", r"verification code",

        r"email", r"e-mail", r"електронн", r"телефон", r"phone number",

        r"отримайте виплату", r"компенсація", r"допомога", r"subsidy", r"benefit",
        r"виграш", r"подарунок", r"приз", r"даруємо", r"ми вибрали вас",

        r"держпослуги", r"держслужба", r"bank support", r"customer support",
        r"служба підтримки", r"служба безпеки", r"security team",

        r"submit", r"continue", r"продовжити", r"send", r"надіслати",
        r"confirm", r"verify", r"authorize", r"authorize transaction",

        r"forms.app", r"google forms", r"formsite", r"typeform",
        r"surveymonkey", r"jotform",
    ]

    escaped = html_lib.escape(explanation)

    def highlight(m):
        return f'<span class="hl">{html_lib.escape(m.group(0))}</span>'

    for kw in keywords:
        escaped = re.sub(kw, highlight, escaped, flags=re.IGNORECASE)

    css = f"""
    <style>
      .card3 {{
        border: 6px solid var(--border-color, #000);
        border-radius: 10px;
        padding: 10px 14px;
        margin: 4px 0 6px 0;
        font-family: 'Inter', sans-serif;
      }}

      .sp {{ height: 14px; }}

      .card3 h3, .card3 p, .card3 small {{
        margin: 0 !important;
        padding: 0 !important;
        line-height: 1.15;
      }}

      .explanation {{
        font-size: 14px;
        color: #bababa;
        margin-top: 4px;
        line-height: 1.25;
        white-space: pre-wrap;
      }}

      .hl {{
        background: rgba(255,235,59,0.42);
        padding: 0 4px;
        border-radius: 3px;
        font-weight: 600;
        color: #111;
      }}
    </style>
    """

    screenshot_button = ""
    if screenshot_base64:
        screenshot_button = f"""
    <a href="{screenshot_base64}"
    target="_blank" 
    rel="noopener noreferrer">
    📷 Відкрити скріншот
    </a>
    <div class="sp"></div>
    """

    html_block = f"""{css}
    <div class="card3" style="--border-color: {border}">
      <h3>📝 Аналіз контенту</h3>

      <div class="sp"></div>

      <p><strong>🧪 Висновок:</strong> {verdict_text}</p>

      <div class="sp"></div>

      <p><strong>💬 Пояснення:</strong></p>
      <p class="explanation">{escaped}</p>

      <div class="sp"></div>

      {screenshot_button}

      <small>{html_lib.escape(str(checked_at))}</small>
    </div>
    """

    return html_block


def render_behavior_analyzer(result):
    data = result["data"]

    if data.get("error", None):
        css = f"""
        <style>
          .card-beh-error {{
            border: 6px solid {COLORS.get("unsafe", "#F44336")};
            border-radius: 10px;
            padding: 10px 14px;
            margin: 6px 0 10px 0;
            font-family: 'Inter', sans-serif;
          }}
          .card-beh-error h3 {{
            margin: 0; padding: 0; line-height: 1.15;
          }}
          .msg {{
            margin-top:8px; font-size:14px; color:#C62828; font-weight:600;
          }}
          small {{ color:#888; }}
        </style>
        """

        html_block = f"""
        {css}
        <div class="card-beh-error">
          <h3>🕵️ Аналіз поведінки (behavior analyzer)</h3>
          <div class="sp"></div>
          <p class="msg">❌ Аналіз не вдався. Сервіс повернув помилку: <strong>{safe_error_text(data.get("error"))}</strong>
        </div>
        """

        return html_block

    results = data.get("results", []) or []

    redirects = dom_changes_count = new_windows_count = alerts_count = 0
    rows_html = []

    for i, entry in enumerate(results, start=1):
        action = entry.get("action", {}) or {}
        action_type = action.get("action", "unknown")
        action_type = 'Заповнення' if action_type == "fill" else 'Клік' if action_type == "click" else html_lib.escape(str(action_type))
        label = action.get("field_label") or action.get("selector_text") or action.get("selector") or ""
        label = html_lib.escape(str(label))

        consequences = []

        if entry.get("redirect") or (
            entry.get("url_before") and entry.get("url_after") and entry.get("url_before") != entry.get("url_after")
        ):
            redirects += 1
            before = html_lib.escape(str(entry.get("url_before") or ""))
            after = html_lib.escape(str(entry.get("url_after") or ""))
            consequences.append(f"🔁 Редирект: {before} → {after}")

        if entry.get("dom_changed"):
            dom_changes_count += 1
            percent = entry.get("dom_change_percent", 0)
            consequences.append(f"🧩 Зміна DOM: {percent:.1f}%")

        if entry.get("new_window_opened") or (entry.get("new_window_urls") or []):
            new_windows_count += 1
            urls = ", ".join(html_lib.escape(u) for u in (entry.get("new_window_urls") or []))
            consequences.append(f"🪟 Відкрито нові вікна: {urls or '—'}")

        if entry.get("alert_present"):
            alerts_count += 1
            text = html_lib.escape(str(entry.get("alert_text") or ""))
            consequences.append(f"⚠️ Спливаюче повідомлення: {text or '—'}")

        content_report = entry.get("content_report") or {}
        if content_report.get("explanation"):
            exp = str(content_report['explanation'])
            translator = GoogleTranslator(source='en', target='uk')
            try:
                exp_en = translator.translate(exp)
            except Exception:
                exp_en = exp
            exp = exp_en
            consequences.append(f"🤖 Контентний аналіз: {html_lib.escape(exp)}")

            screenshot_b64 = content_report.get("screenshot_base64")
            if screenshot_b64:
                consequences.append(f'<a href="{screenshot_b64}" target="_blank" rel="noopener noreferrer">📷 Скріншот контенту</a>')

        if content_report.get("verdict"):
            consequences.append("🧪 Висновок аналізу: ❌ виявлено підозрілий контент")

        if not consequences:
            consequences.append("<span style='color:#999;'>Без наслідків</span>")

        rows_html.append(
            f"<div class='action-row'><div class='action-title'><strong>{i}. {action_type}</strong> - {label}</div>"
            f"<div class='action-consequences'>{'<br>'.join(consequences)}</div></div>"
        )

    total_alerts = alerts_count
    total_redirects = redirects
    total_dom = dom_changes_count
    total_new_windows = new_windows_count
    found_any = (total_alerts + total_redirects + total_dom + total_new_windows) > 0

    if not found_any:
        verdict_text = "✅ Нічого підозрілого не знайдено"
        border = COLORS["safe"]
        summary = "Жодних редиректів, змін DOM, нових вікон чи alert не виявлено."
    else:
        verdict_text = "⌛ Виявлені можливі дії"
        border = COLORS["probable_unsafe"]
        parts = []
        if total_redirects:
            parts.append(f"{total_redirects} редирект(ів)")
        if total_dom:
            parts.append(f"{total_dom} змін(и) DOM")
        if total_new_windows:
            parts.append(f"{total_new_windows} нових вікон(а)")
        if total_alerts:
            parts.append(f"{total_alerts} alert(ів)")
        summary = "Знайдено: " + ", ".join(parts)

    css = f"""
    <style>
      .card-beh {{
        border: 6px solid var(--border-color, #000);
        border-radius: 10px;
        padding: 10px 14px;
        margin: 4px 0 6px 0;
        font-family: 'Inter', sans-serif;
      }}
      .summary {{ margin-top:6px; font-weight:700; font-size:15px; }}
      .rows-container {{
        max-height: 200px;
        overflow-y: auto;
        padding-right: 6px;
        scrollbar-width: thin;
      }}
      .action-row {{
        margin-bottom:10px;
        padding: 0 8px 0px 8px;
        border-radius:2px;
        background: rgba(0,0,0,0.02);
      }}
      .action-title {{ font-size:14px; color:#999; margin-bottom:2px;}}
      .action-consequences {{ font-size:14px; color:#999; margin-left:16px; }}
    </style>
    """

    html_block = textwrap.dedent(f"""
    {css}
    <div class="card-beh" style="--border-color: {border}">
      <h3>🕵️ Аналіз поведінки</h3>

      <p class="summary">🧪 Висновок: {verdict_text}</p>
      <p class="meta">{html_lib.escape(summary)}</p>
      
      <p class="meta">Деталі дій та наслідків:</p>
      <div class="rows-container">{''.join(rows_html)}</div>

      <div class="sp"></div>
      <small>{html_lib.escape(str(data.get("checked_at", "")))}</small>
    </div>
    """).strip()

    return html_block


def render_behavior_summary(result):
    data = result["data"]

    if data.get("error", None):
        css = f"""
                <style>
                    .card-beh-summary-error {{
                    border: 6px solid {COLORS.get("unsafe", "#F44336")};
                    border-radius: 10px;
                    padding: 10px 14px;
                    margin: 6px 0 10px 0;
                    font-family: 'Inter', sans-serif;
                    }}
                    .card-beh-summary-error h3 {{
                    margin: 0; padding: 0; line-height: 1.15;
                    }}
                    .msg {{
                    margin-top:8px; font-size:14px; color:#C62828;
                    font-weight:600;
                    }}
                    small {{ color:#888; }}
                </style>
                """

        html_block = textwrap.dedent(f"""
            {css}
            <div class="card-beh-summary-error">
              <h3>📊 Підсумок аналізу поведінки</h3>
              <div class="sp"></div>
              <p class="msg">❌ Помилка при отриманні підсумкових даних з сервісу аналізу поведінки:
                <strong>{safe_error_text(data.get("error"))}</strong>
              </p>
            </div>
            """).strip()

        return html_block

    verdict = bool(data.get("verdict", False))
    explanation = data.get("explanation", "") or ""
    checked_at = data.get("checked_at", "")

    translator = GoogleTranslator(source='en', target='uk')
    try:
        explanation_uk = translator.translate(explanation)
    except Exception:
        explanation_uk = explanation
    explanation = explanation_uk
    explanation_escaped = html_lib.escape(explanation)

    if verdict:
        border = COLORS.get("unsafe", "#F44336")
        verdict_text = "❌ Виявлено скоординовану фішингову активність"
    else:
        border = COLORS.get("safe", "#4CAF50")
        verdict_text = "✅ Підозрілої активності не виявлено"

    summary_payload = data.get("summary_payload", {}) or {}
    analyzed_root = summary_payload.get("analyzed_root", []) or []
    analyzed_children = summary_payload.get("analyzed_children", []) or []
    redirect_chain = summary_payload.get("redirect_chain", []) or []
    origin_url = summary_payload.get("origin") or result.get("url") or ""

    url_services = {}

    for item in (analyzed_root + analyzed_children):
        svc_name = item.get("service")
        url = item.get("url")
        svc_data = item.get("data", {}) or {}
        if not url or not svc_name:
            continue
        url_services.setdefault(url, {})[svc_name] = svc_data

    redirect_events = {}
    new_window_events = []

    for item in (analyzed_root + analyzed_children):
        if item.get("service") != "behavior_analyzer":
            continue
        beh_data = (item.get("data") or {})
        for entry in beh_data.get("results", []) or []:
            ub = entry.get("url_before")
            ua = entry.get("url_after")
            act = entry.get("action", {}) or {}
            act_type_raw = act.get("action") or "action"
            if act_type_raw == "click":
                act_type = "клік"
            elif act_type_raw == "fill":
                act_type = "заповнення"
            else:
                act_type = act_type_raw
            label = act.get("field_label") or act.get("selector_text") or act.get("selector") or ""
            label = str(label).strip()
            if label:
                desc = f"{act_type} «{label}»"
            else:
                desc = act_type

            if ub and ua and entry.get("redirect"):
                redirect_events[(ub, ua)] = desc

            if entry.get("new_window_opened") or (entry.get("new_window_urls") or []):
                for nu in (entry.get("new_window_urls") or []):
                    new_window_events.append((ub or item.get("url", ""), nu, desc))

    def summarize_threat_intel(svc_data):
        if svc_data.get("error", None):
            return f"❌ Перевірка у базах: помилка отримання даних: {html_lib.escape(str(svc_data.get('error')))}"

        vt = svc_data.get("virustotal", {}) or {}
        wr = svc_data.get("webrisk", {}) or {}
        stats = vt.get("stats", {}) or {}
        if not stats:
            return "ℹ️ Перевірка у базах: дані відсутні"

        harmless = int(stats.get("harmless", 0))
        suspicious = int(stats.get("suspicious", 0))
        malicious = int(stats.get("malicious", 0))
        undetected = int(stats.get("undetected", 0))
        total = max(harmless + suspicious + malicious + undetected, 1)

        wr_risk = 0 if wr.get("safe") else 1
        vt_risk = (suspicious + malicious) / total if total else 0
        final_risk = 0.5 * wr_risk + 0.5 * vt_risk

        if final_risk < 0.10:
            icon = "✅"
            text = "URL виглядає безпечним"
        elif final_risk < 0.30:
            icon = "⚠️"
            text = "URL скоріше безпечний"
        elif final_risk < 0.60:
            icon = "⚠️"
            text = "URL може бути ризиковим"
        else:
            icon = "❌"
            text = "URL має ознаки небезпеки"

        return f"{icon} Перевірка в базах: {text} ({suspicious + malicious}/{total} підозрілих/шкідливих спрацьовувань)"

    def summarize_domain(svc_data):
        if svc_data.get("error", None):
            return f"❌ Аналіз домену: помилка отримання даних: {html_lib.escape(str(svc_data.get('error')))}"

        dom = svc_data.get("virustotal_domain", {}) or {}
        stats = dom.get("stats", {}) or {}
        harmless = int(stats.get("harmless", 0))
        suspicious = int(stats.get("suspicious", 0))
        malicious = int(stats.get("malicious", 0))
        undetected = int(stats.get("undetected", 0))
        total = max(harmless + suspicious + malicious + undetected, 1)
        risk = (suspicious + malicious) / total
        if not stats:
            return "ℹ️ Аналіз домену: дані відсутні"

        if malicious == 0 and suspicious == 0:
            icon = "✅"
            text = "домен виглядає безпечним"
        elif risk <= 0.2:
            icon = "⚠️"
            text = "домен скоріше безпечний"
        elif risk <= 0.5:
            icon = "⚠️"
            text = "домен може бути ризиковим"
        else:
            icon = "❌"
            text = "домен має ознаки небезпеки"

        domain_name = dom.get("domain", "") or ""
        if domain_name:
            domain_name = f" ({domain_name})"

        return f"{icon} Домен: {text}{domain_name} ({suspicious + malicious}/{total} підозрілих/шкідливих)"

    def summarize_content(svc_data):
        if not svc_data:
            return "ℹ️ Контент: дані відсутні"

        error = svc_data.get("error")
        if error:
            return (
                "❌ Аналіз контенту: помилка отримання даних: "
                f"{html_lib.escape(str(error))}"
            )

        verdict = bool(svc_data.get("verdict", False))
        explanation = html_lib.escape(svc_data.get("explanation", "") or "")
        translator = GoogleTranslator(source='en', target='uk')
        try:
            explanation_en = translator.translate(explanation)
        except Exception:
            explanation_en = explanation
        explanation = explanation_en
        screenshot_b64 = svc_data.get("screenshot_base64")

        status = "❌ Контент: виявлено ознаки фішингу" if verdict \
            else "✅ Контент: підозрілих ознак не виявлено"

        screenshot_html = (
            f'<a href="{screenshot_b64}" target="_blank" rel="noopener noreferrer">'
            f"📷 Скріншот контенту</a>"
            if screenshot_b64 else ""
        )

        return f"""
        <div>{status}</div>
        <div>Пояснення: {explanation}</div>
        {screenshot_html}
        """

    def summarize_behavior(svc_data):
        if svc_data.get("error", None):
            return f"❌ Аналіз поведінки: помилка отримання даних: {html_lib.escape(str(svc_data.get('error')))}"

        results = svc_data.get("results", []) or []
        redirects = dom_changes = new_windows = alerts = 0
        for e in results:
            if e.get("redirect"):
                redirects += 1
            if e.get("dom_changed"):
                dom_changes += 1
            if e.get("new_window_opened") or (e.get("new_window_urls") or []):
                new_windows += 1
            if e.get("alert_present"):
                alerts += 1

        if redirects == dom_changes == new_windows == alerts == 0:
            return "✅ Поведінка: підозрілих дій не виявлено"
        parts = []
        if redirects:
            parts.append(f"{redirects} редирект(ів)")
        if dom_changes:
            parts.append(f"{dom_changes} змін(и) DOM")
        if new_windows:
            parts.append(f"{new_windows} нових вікон(а)")
        if alerts:
            parts.append(f"{alerts} alert(ів)")
        return "❌ Поведінка: " + ", ".join(parts)

    def build_services_summary(url):
        svc_map = url_services.get(url, {}) or {}
        parts = []

        if "domain_analyzer" in svc_map:
            parts.append(("text", summarize_domain(svc_map["domain_analyzer"])))

        if "threat_intel" in svc_map:
            parts.append(("text", summarize_threat_intel(svc_map["threat_intel"])))

        if "content_analyzer" in svc_map:
            parts.append(("html", summarize_content(svc_map["content_analyzer"])))

        if "behavior_analyzer" in svc_map:
            parts.append(("text", summarize_behavior(svc_map["behavior_analyzer"])))

        if not parts:
            return ""

        rendered = []
        for part_type, payload in parts:
            if part_type == "text":
                rendered.append(html_lib.escape(payload))
            else:  # html
                rendered.append(payload)

        return "<br>".join(rendered)

    rows_html = []

    for node in redirect_chain:
        depth = int(node.get("depth", 0) or 0)
        source = node.get("source") or ""
        children = node.get("children", []) or []

        for child in children:
            src_disp = html_lib.escape(source or "—")
            child_disp = html_lib.escape(child)

            margin_left = max(depth, 0) * 16

            event_desc = redirect_events.get((source, child))
            if event_desc:
                event_html = "Подія: " + html_lib.escape(event_desc)
            else:
                event_html = ""

            services_html = build_services_summary(child)
            services_block = f"<div class='bs-step-services'>{services_html}</div>" if services_html else ""

            rows_html.append(
                f"<div class='bs-step' style='margin-left:{margin_left}px'>"
                f"<div class='bs-step-header'>"
                f"<span class='bs-tag-level'>Рівень {depth + 1}</span>"
                f"{src_disp} &nbsp;→&nbsp; <strong>{child_disp}</strong>"
                f"</div>"
                f"<div class='bs-step-meta'>{event_html}</div>"
                f"{services_block}"
                f"</div>"
            )

    extra_windows_html = ""
    if new_window_events:
        win_rows = []
        for parent, new_url, desc in new_window_events:
            parent_disp = html_lib.escape(parent or "—")
            new_disp = html_lib.escape(new_url or "—")
            desc_disp = html_lib.escape(desc)
            services_html = build_services_summary(new_url)
            services_block = f"<div class='bs-step-services'>{services_html}</div>" if services_html else ""
            win_rows.append(
                f"<div class='bs-step' style='margin-left:16px'>"
                f"<div class='bs-step-header'>"
                f"🪟 {parent_disp} &nbsp;→&nbsp; <strong>{new_disp}</strong>"
                f"</div>"
                f"<div class='bs-step-meta'>Подія: {desc_disp}</div>"
                f"{services_block}"
                f"</div>"
            )
        extra_windows_html = (
            "<div class='beh-section-title'>🪟 Нові вікна</div>"
            "<div class='bs-tree'>" + "".join(win_rows) + "</div>"
        )

    if len(redirect_events) == 0 and len(new_window_events) == 0:
        rows_html.append(
            "<div class='bs-step'>"
            "<div class='bs-step-header'><strong>Ланцюжок переходів відсутній</strong></div>"
            "<div class='bs-step-services' style='color:#bbb;'>"
            "Редиректи або нові вікна не були зафіксовані."
            "</div></div>"
        )

    tree_html = "".join(rows_html)

    chain_urls = []
    if origin_url:
        chain_urls.append(origin_url)

    for node in redirect_chain:
        for child in (node.get("children") or []):
            if child not in chain_urls:
                child_cropped = child[:100] + ("…" if len(child) > 100 else "")
                chain_urls.append(child_cropped)

    chain_line = ""
    if chain_urls:
        chain_line = " → ".join(html_lib.escape(u) for u in chain_urls)

    exp_html = explanation_escaped.strip().replace("\n", "<br>")

    css = f"""
    <style>
      .card-beh-summary {{
        border: 6px solid var(--border-color, #000);
        border-radius: 10px;
        padding: 10px 14px;
        margin: 6px 0 10px 0;
        font-family: 'Inter', sans-serif;
      }}
      .card-beh-summary h3,
      .card-beh-summary p,
      .card-beh-summary small {{
        margin: 0 !important;
        padding: 0 !important;
        line-height: 1.15;
      }}
      .sp {{ height: 14px; }}
      .beh-short {{
        font-size: 15px;
        font-weight: 700;
      }}
      .beh-expl {{
        font-size: 14px;
        color: #bababa;
        margin-top: 4px;
        line-height: 1.25;
        white-space: pre-wrap;
      }}
      .beh-section-title {{
        margin-top: 10px;
        font-size: 14px;
        font-weight: 600;
      }}
      .beh-meta {{
        margin-top: 4px;
        font-size: 12px;
        color: #999;
      }}
      .bs-tree {{
        margin-top: 4px;
      }}
      .bs-step {{
        border-radius: 6px;
        padding: 6px 8px;
        margin-bottom: 6px;
        background: rgba(0,0,0,0.02);
      }}
      .bs-step-header {{
        font-size: 13px;
        font-weight: 600;
        color: #ddd;
      }}
      .bs-step-meta {{
        font-size: 12px;
        color: #999;
        margin-top: 2px;
      }}
      .bs-step-services {{
        font-size: 12px;
        color: #999;
        margin-top: 2px;
      }}
      .bs-tag-level {{
        display: inline-block;
        font-size: 11px;
        padding: 1px 6px;
        border-radius: 10px;
        background: rgba(0,0,0,0.20);
        margin-right: 6px;
        color: #eee;
      }}
    </style>
    """

    html_block = f"""
    {css}
    <div class="card-beh-summary" style="--border-color: {border}">
      <h3>🧩 Підсумковий аналіз поведінки</h3>

      <div class="sp"></div>

      <p class="beh-short">🧪 Висновок: {verdict_text}</p>
      <div class="sp"></div>

      <p><strong>💬 Пояснення сценарію:</strong></p>
      <p class="beh-expl">{exp_html}</p>

      {"<p class='beh-meta'>Ланцюжок переходів: " + chain_line + "</p>" if chain_line else ""}

      <div class="beh-section-title">🔗 Деталі переходів та результати сервісів</div>
      <div class="bs-tree">
        {tree_html}
      </div>"""

    if extra_windows_html:
        html_block += extra_windows_html
    html_block += f"""
      <div class="sp"></div>
      <small>{html_lib.escape(str(checked_at))}</small>
    </div>
    """

    return html_block


if start_button and url:
    resp = requests.post(
        RISK_AGGREGATOR_URL,
        json={"url": url},
        stream=True,
        timeout=360,
    )

    if resp.status_code != 200:
        try:
            err_json = resp.json()
            err_msg = err_json.get("error", "Помилка під час запиту.")
        except Exception:
            err_msg = "Помилка під час запиту."

        st.error(f"❌ {err_msg}")
        st.stop()

    progress = st.progress(0)

    top_summary_slot = st.empty()

    row1_col1, row1_col2 = st.columns(2)
    summary_slot = st.empty()

    card_slots = {
        "threat_intel": row1_col1.empty(),
        "behavior_analyzer": row1_col1.empty(),
        "domain_analyzer": row1_col2.empty(),
        "content_analyzer": row1_col2.empty(),
        "behavior_summary": summary_slot,
    }

    loading_by_service = {
        "threat_intel": "Перевірка у базах загроз",
        "domain_analyzer": "Аналіз домену",
        "content_analyzer": "Аналіз контенту",
        "behavior_analyzer": "Аналіз поведінки",
        "behavior_summary": "Підсумок поведінки",
    }

    for key, slot in card_slots.items():
        slot.markdown(
            f"<div style='padding:20px;color:#888'>⏳ Опрацювання: {loading_by_service[key]}...</div>",
            unsafe_allow_html=True
        )

    collected_values = {
        "threat_intel": None,
        "domain_analyzer": None,
        "content_analyzer": None,
        "behavior_summary": None,
    }

    events = []

    for raw_line in resp.iter_lines():
        if not raw_line:
            continue

        try:
            line = raw_line.decode("utf-8")
        except:
            continue

        if not line.startswith("data:"):
            continue

        json_data = line.replace("data:", "", 1).strip()

        try:
            parsed = json.loads(json_data)
        except Exception:
            continue

        events.append(parsed)
        service = parsed.get("service")
        values_for_service = {}

        if service in card_slots:
            container = card_slots[service]

            if service == "threat_intel":
                html = render_threat_intel(parsed)
                if parsed.get("data", {}).get("error", None) is None:
                    values_for_service["threat_intel"] = {
                        "webrisk_safe": parsed.get("data", {}).get("webrisk", {}).get("safe", True),
                        "vt_stats": parsed.get("data", {}).get("virustotal", {}).get("stats", {})
                    }
            elif service == "domain_analyzer":
                html = render_domain_analyzer(parsed)
                if parsed.get("data", {}).get("error", None) is None:
                    values_for_service["domain_analyzer"] = {
                        "vt_domain_stats": parsed.get("data", {}).get("virustotal_domain", {}).get("stats", {})
                    }

            elif service == "content_analyzer":
                html = render_content_analyzer(parsed)
                if parsed.get("data", {}).get("error", None) is None:
                    values_for_service["content_analyzer"] = {
                        "verdict": parsed.get("data", {}).get("verdict", False)
                    }

            elif service == "behavior_analyzer":
                html = render_behavior_analyzer(parsed)

            elif service == "behavior_summary":
                html = render_behavior_summary(parsed)
                if parsed.get("data", {}).get("error", None) is None:
                    values_for_service["behavior_summary"] = {
                        "verdict": parsed.get("data", {}).get("verdict", False)
                    }

            container.markdown(html, unsafe_allow_html=True)

        for svc, val in values_for_service.items():
            collected_values[svc] = val
            print(f"Collected values updated – {svc}: {val}")

        progress.progress(min(len(events) / 5, 1.0))

    try:
        score_resp = requests.post(
            RISK_AGGREGATOR_SCORE_URL,
            json={"values": collected_values},
            timeout=30,
        )

        if score_resp.status_code == 200:
            score_json = score_resp.json()
            integro_score = score_json.get("integro_score", "N/A")
            integro_explanation = score_json.get("explanation", "")
            formula = score_json.get("formula", "")

            def pick_color(score):
                if not isinstance(score, (int, float)):
                    return COLORS["probable_safe"]
                if score <= 25:
                    return COLORS["safe"]
                elif score <= 50:
                    return COLORS["probable_safe"]
                elif score <= 75:
                    return COLORS["probable_unsafe"]
                else:
                    return COLORS["unsafe"]

            border_color = pick_color(float(integro_score) if integro_score != "N/A" else 50)

            top_summary_slot.markdown(
                f"""
                <div style="padding:15px; border: 6px solid {border_color}; border-radius:10px; font-family: 'Inter', sans-serif;">
                    <h2>🧮 Оцінка ризику: {html_lib.escape(str(integro_score))} / 100</h2>
                    <p style="font-size:14px; color:#666;">Формула розрахунку: <em>{html_lib.escape(str(formula))}</em></p>
                    <p style="color:#333; font-size:14px;">{html_lib.escape(str(integro_explanation))}</p>
                </div>
                <div style="margin:25px 0 15px 0; width:100%; height:2px; 
                background:linear-gradient(to right, #ccc, #eee, #ccc);
                border-radius:2px;">
                """,
                unsafe_allow_html=True
            )


    except Exception as e:
        top_summary_slot.markdown(
            f"<div style='padding:10px;color:red'>❌ Помилка при розрахунку інтегрального ризику: {e}</div>",
            unsafe_allow_html=True
        )

    progress.empty()



