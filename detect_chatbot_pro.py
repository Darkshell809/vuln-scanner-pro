import asyncio
import sys
import json
import re
from playwright.async_api import async_playwright

# Common AI Chatbot Signatures
SIGNATURES = {
    "Amelia (SoundHound)": {
        "patterns": ["amelia.com", "ipsoft.com", "Amelia", "IPsoft", "AmeliaWidget"],
        "elements": ["#amelia-container", ".amelia-chat-window", ".ipsoft-widget"]
    },
    "LeO (MeetLeO)": {
        "patterns": ["meetleo.com", "app.meetleo.com", "window.LeO", "window.MeetLeO"],
        "elements": ["#leo-widget-container", ".meetleo-launcher"]
    },
    "Intercom": {
        "patterns": ["intercomcdn.com", "widget.intercom.io", "window.Intercom"],
        "elements": ["#intercom-container", ".intercom-app"]
    },
    "Drift": {
        "patterns": ["drift.com", "js.driftt.com", "window.drift"],
        "elements": ["#drift-widget-container"]
    },
    "Zendesk": {
        "patterns": ["zdassets.com", "static.zdassets.com", "window.zE"],
        "elements": ["#ze-snippet"]
    },
    "HubSpot": {
        "patterns": ["js.hs-scripts.com", "js.usemessages.com", "HubSpotConversations"],
        "elements": ["#hubspot-messages-iframe-container"]
    },
    "LivePerson": {
        "patterns": ["lpsnmedia.net", "lptag.liveperson.net", "lpTag"],
    },
    "Salesforce": {
        "patterns": ["salesforceliveagent.com", "embeddedservice"],
        "elements": [".embeddedServiceHelpButton"],
    },
    "Ada": {
        "patterns": ["ada.support", "static.ada.support", "adaReady", "adaEmbed"],
    }
}

async def detect_chatbot(url):
    results = {
        "url": url,
        "chatbot_found": False,
        "providers": [],
        "network_matches": [],
        "dom_matches": [],
        "global_matches": []
    }

    async with async_playwright() as p:
        # Launch browser
        browser = await p.chromium.launch(headless=True)
        # Use a realistic User-Agent
        context = await browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
        )
        page = await context.new_page()

        # Track network requests
        network_logs = []
        page.on("request", lambda request: network_logs.append(request.url))

        print(f"[*] Navigating to {url}...")
        try:
            # Use 'domcontentloaded' for faster loading and bypass some busy network issues
            await page.goto(url, wait_until="domcontentloaded", timeout=45000)
            # Wait extra time for widgets to pop up
            await asyncio.sleep(8)
        except Exception as e:
            print(f"[!] Error or timeout for {url}: {e}")
            # Continue anyway as we might have partial data or can still inspect the page
            pass

        # Get full page source after JS execution
        try:
            full_html = await page.content()
        except:
            full_html = ""

        # 1. Analyze Network Requests
        for provider, sigs in SIGNATURES.items():
            for pattern in sigs.get("patterns", []):
                if any(pattern.lower() in req.lower() for req in network_logs):
                    results["providers"].append(provider)
                    results["network_matches"].append({"provider": provider, "match": pattern})
                    break

        # 2. Analyze live DOM and Full HTML
        for provider, sigs in SIGNATURES.items():
            if provider in results["providers"]: continue
            
            # Check elements
            for element in sigs.get("elements", []):
                try:
                    if await page.query_selector(element):
                        results["providers"].append(provider)
                        results["dom_matches"].append({"provider": provider, "match": element})
                        break
                except:
                    pass
            
            if provider in results["providers"]: continue

            # Check full HTML source
            for pattern in sigs.get("patterns", []):
                if pattern in full_html:
                    results["providers"].append(provider)
                    results["dom_matches"].append({"provider": provider, "match": f"source_match_{pattern}"})
                    break

        # 3. Analyze Global Variables
        for provider, sigs in SIGNATURES.items():
            if provider in results["providers"]: continue
            for pattern in sigs.get("patterns", []):
                # Only check patterns that look like global variables
                if pattern.startswith("window.") or re.match(r'^[A-Z][a-zA-Z]+$', pattern):
                    var_name = pattern.replace("window.", "")
                    is_defined = await page.evaluate(f"typeof {var_name} !== 'undefined'")
                    if is_defined:
                        results["providers"].append(provider)
                        results["global_matches"].append({"provider": provider, "match": var_name})
                        break

        # Final check for "chat" related elements if no provider found
        if not results["providers"]:
            chat_keywords = ["chat", "bot", "assistant", "help"]
            for kw in chat_keywords:
                # Look for buttons or fixed elements with these keywords
                found = await page.evaluate(f"""() => {{
                    const el = document.body.innerText.toLowerCase();
                    return el.includes('{kw}');
                }}""")
                if found:
                    results["dom_matches"].append({"match": kw, "type": "keyword_in_text"})

        results["chatbot_found"] = len(results["providers"]) > 0
        results["providers"] = list(set(results["providers"]))
        
        await browser.close()
        return results

async def main():
    if len(sys.argv) < 2:
        print("Usage: python3 detect_chatbot_pro.py <url1> <url2> ...")
        print("Example: python3 detect_chatbot_pro.py https://example.com")
        sys.exit(1)
        
    urls = sys.argv[1:]
    
    final_results = []
    for url in urls:
        if not url.startswith("http"):
            url = "https://" + url
        res = await detect_chatbot(url)
        final_results.append(res)
    
    print("\n" + "="*50)
    print("PRO DETECTION RESULTS (DYNAMIC)")
    print("="*50)
    print(json.dumps(final_results, indent=2))

if __name__ == "__main__":
    asyncio.run(main())