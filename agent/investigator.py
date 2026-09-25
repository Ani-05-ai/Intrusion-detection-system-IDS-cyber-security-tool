import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq

load_dotenv()

llm = ChatGroq(
    model="openai/gpt-oss-20b",
    api_key=os.getenv("GROQ_API_KEY"),
    temperature=0.3
)


def investigate_alert(alert, related_alerts):
    related_summary = "\n".join([
        f"- {r.get('severity', 'unknown')} | {[rule['rule'] for rule in r.get('rules', [])]} | event: {r.get('event', {})}"
        for r in related_alerts
    ]) or "No related historical alerts found."

    prompt = f"""You are a SOC (Security Operations Center) analyst assistant.

CURRENT ALERT:
Severity: {alert.get('severity')}
Detection source: {alert.get('source')}
Rules triggered: {[r['rule'] for r in alert.get('rules', [])]}
Event details: {alert.get('event')}

RELATED HISTORICAL ALERTS (same source or pattern):
{related_summary}

Provide a concise investigation summary covering:
1. What this alert likely means (in plain language)
2. Whether the historical pattern suggests this is part of a larger attack
3. Recommended next action for the analyst

Keep it under 150 words."""

    response = llm.invoke(prompt)
    return response.content