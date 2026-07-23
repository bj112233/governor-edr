# services/agent/skill_descriptions.py
"""Semantic descriptions for embedding-based skill routing.

Extracted from skill_keywords.py (SRP). English descriptions for embedding
models (trained on English corpora).
"""

_SKILL_DESCRIPTIONS: dict[str, str] = {
    "skill_news-monitor": "News headlines, current events, breaking news, politics, government, Israel, RSS feeds",
    "skill_stocks-skill": "Stock prices, market data, ticker quotes, financial instruments, Bitcoin, Ethereum, cryptocurrency, crypto, BTC, ETH",
    "skill_currency-skill": "Currency exchange rates, dollar, euro, shekel, conversion, foreign exchange, forex, money value",
    "skill_weather-skill": "Weather forecast, temperature, rain, humidity, wind, cold, heat, climate, meteorology",
    "skill_translator-skill": "Translation, translate text, Hebrew to English, English to Hebrew, language conversion",
    "skill_geocode-skill": "Geocoding, distance, travel, route, address, location, map, driving directions, navigation, airport, flight",
    "skill_firewall-skill": "Firewall rules, block IP, unblock, network security, ports, connections, traffic filtering",
    "skill_intel-skill": "IP reputation, domain reputation, whois, DNS lookup, malware, virus, threat intelligence, suspicious, hash check",
    "skill_crypto-skill": "Cryptography tools, SHA256, MD5, JWT, password generation, HMAC, base64 encode decode, encryption, hashing. NOT for cryptocurrency prices — use skill_stocks-skill with crypto command for Bitcoin/Ethereum prices.",
    "skill_report-maker": "System reports, status reports, logs, events, daily digest, documentation, PDF report, analysis report",
    "skill_web-scraper": "Web scraping, extract data from websites, URL fetching, HTML parsing, article extraction, Google, Wikipedia, price comparison",
    "skill_file-analyst": "File analysis, PDF, OCR, image analysis, document reading, contract review, Excel, Word, CSV, text files, screenshots",
    "skill_pcap-analyst": "PCAP network capture analysis, DNS queries, TLS SNI, traffic dump, packet inspection, IOC extraction from network traffic, Wireshark",
    "skill_email-forensics": "Email forensics, phishing analysis, EML parsing, SPF DKIM DMARC, authentication results, email headers, phishing detection, Outlook MSG",
    "skill_persistence-hunter": "Windows persistence mechanisms, registry Run RunOnce keys, startup folders, scheduled tasks, WMI event subscriptions, autorun, MITRE ATT&CK persistence",
}
