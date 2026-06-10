import requests
from bs4 import BeautifulSoup
import re
import json
import sys

# Common AI Chatbot Signatures
SIGNATURES = {
    "Intercom": {
        "scripts": ["intercomcdn.com", "widget.intercom.io"],
        "elements": ["#intercom-container", ".intercom-app"],
        "globals": ["Intercom"]
    },
    "Drift": {
        "scripts": ["drift.com", "js.driftt.com"],
        "elements": ["#drift-widget-container"],
        "globals": ["drift"]
    },
    "Zendesk": {
        "scripts": ["zdassets.com", "static.zdassets.com"],
        "elements": ["#ze-snippet"],
        "globals": ["zE"]
    },
    "HubSpot": {
        "scripts": ["js.hs-scripts.com", "js.usemessages.com"],
        "elements": ["#hubspot-messages-iframe-container"],
        "globals": ["HubSpotConversations"]
    },
    "Salesforce": {
        "scripts": ["salesforceliveagent.com", "embeddedservice"],
        "elements": [".embeddedServiceHelpButton"],
    },
    "LivePerson": {
        "scripts": ["lpsnmedia.net", "lptag.liveperson.net", "lpTag"],
        "globals": ["lpTag"]
    },
    "Ada": {
        "scripts": ["ada.support", "static.ada.support", "adaReady", "adaEmbed"],
        "globals": ["adaReady", "adaEmbed"]
    },
    "Tidio": {
        "scripts": ["tidio.com", "code.tidio.co"],
        "elements": ["#tidio-chat"]
    },
    "Crisp": {
        "scripts": ["client.crisp.chat"],
        "globals": ["$crisp"]
    },
    "Genesys": {
        "scripts": ["genesys.com/widgets", "_genesys"],
        "globals": ["_genesys"]
    },
    "Watson Assistant": {
        "scripts": ["watson-assistant.watson.cloud"],
    }
}

KEYWORDS = [
    "chat", "chatbot", "virtual assistant", "how can i help", 
    "ask a question", "live chat", "start conversation", "bot"
]

def analyze_site(url):
    print(f"[*] Analyzing {url}...")
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
        response.raise_for_status()
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
    except Exception as e:
        return {"error": str(e)}

    findings = []
    
    # Check Scripts and Raw HTML
    scripts = soup.find_all('script', src=True)
    script_srcs = [s['src'] for s in scripts]
    
    for provider, sigs in SIGNATURES.items():
        found_provider = False
        
        # 1. Check script sources
        for script_sig in sigs.get("scripts", []):
            if any(script_sig in src for src in script_srcs):
                findings.append({"provider": provider, "type": "script_tag_match", "match": script_sig})
                found_provider = True
                break
        
        if found_provider: continue
            
        # 2. Check elements (IDs/Classes)
        for element_sig in sigs.get("elements", []):
            if soup.select_one(element_sig):
                findings.append({"provider": provider, "type": "element_match", "match": element_sig})
                found_provider = True
                break

        if found_provider: continue

        # 3. Check in raw HTML (most robust for embedded strings/JSON)
        for sig_type in ["scripts", "globals"]:
            for sig in sigs.get(sig_type, []):
                if sig in html:
                    findings.append({"provider": provider, "type": "raw_html_match", "match": sig})
                    found_provider = True
                    break
            if found_provider: break

    # Keyword Search
    keyword_matches = []
    for keyword in KEYWORDS:
        # Search in text nodes
        if re.search(r'\b' + re.escape(keyword) + r'\b', html, re.IGNORECASE):
            keyword_matches.append(keyword)

    return {
        "url": url,
        "chatbot_found": len(findings) > 0,
        "providers": findings,
        "keyword_matches": list(set(keyword_matches))
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 detect_chatbot.py <url1> <url2> ...")
        print("Example: python3 detect_chatbot.py https://example.com")
        sys.exit(1)
        
    urls = sys.argv[1:]
    
    results = []
    for url in urls:
        if not url.startswith("http"):
            url = "https://" + url
        res = analyze_site(url)
        results.append(res)
    
    print("\n" + "="*50)
    print("DETECTION RESULTS")
    print("="*50)
    print(json.dumps(results, indent=2)) umps(results, indent=2)) 
    print(json.dumps(results, indent=2))
