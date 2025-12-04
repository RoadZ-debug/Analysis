import requests
import re
import json
import time
from urllib.parse import quote
from lxml import html

def scrape_baidu_news(keyword):
    """
    Scrape Baidu News for a given keyword.
    Returns a list of dictionaries containing:
    - title
    - summary
    - cover (image url)
    - url (original url)
    - source
    """
    
    base_url = "https://www.baidu.com/s"
    encoded_keyword = quote(keyword)
    
    # Parameters from user request
    params = {
        "rtt": "1",
        "bsst": "1",
        "cl": "2",
        "tn": "news",
        "rsv_dl": "ns_pc",
        "word": keyword
    }
    
    # Headers from user request
    headers = {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "accept-encoding": "gzip, deflate", 
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
        "cache-control": "max-age=0",
        "connection": "keep-alive",
        "cookie": "BAIDUID=C2EBF1B529B99DFEC6C6DE99E893ED24:FG=1;", # Simplified cookie
        "host": "www.baidu.com",
        "referer": "https://news.baidu.com/",
        "sec-ch-ua": "\"Chromium\";v=\"142\", \"Microsoft Edge\";v=\"142\", \"Not_A Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-site",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"
    }

    try:
        # Explicitly disable proxies to avoid SOCKS error
        response = requests.get(base_url, params=params, headers=headers, proxies={"http": None, "https": None}, timeout=10)
        response.encoding = 'utf-8'
        
        if response.status_code != 200:
            print(f"Failed to retrieve data: {response.status_code}")
            return []

        html_content = response.text
        
        # Regex to find the s-data JSON blob
        # Pattern matches <!--s-data:{...}-->
        # We use non-greedy match .*? 
        pattern = r'<!--s-data:(\{.*?\})-->'
        matches = re.findall(pattern, html_content)
        
        # Fallback: sometimes Baidu News uses a different structure or the comment is slightly different
        if not matches:
            # Try finding window.data = { ... } or similar structures if the comment one fails
            # But first, let's try a more permissive regex for the comment
            pattern_alt = r's-data:(\{.*?\})'
            matches = re.findall(pattern_alt, html_content)

        results = []
        for match in matches:
            try:
                # Sometimes match might need cleanup if permissive regex is used
                # But the original regex is quite specific.
                
                data = json.loads(match)
                
                # Extract required fields
                # Note: Different result types might have different field names
                # "tpl" field often indicates the type (e.g. "se_st_news", "se_st_timeline")
                
                title = data.get("title", "").replace("<em>", "").replace("</em>", "")
                url = data.get("titleUrl", "")
                
                if not title or not url:
                    continue
                    
                item = {
                    "title": title,
                    "summary": data.get("summary", "").replace("<em>", "").replace("</em>", ""),
                    "cover": data.get("leftImgSrc", "") or data.get("image", "") or data.get("imgUrl", ""), 
                    "url": url,
                    "source": data.get("sourceName", "") or data.get("source", "")
                }
                
                results.append(item)
                    
            except json.JSONDecodeError:
                continue
        
        # If still no results, print debug info to console (visible in terminal)
        if not results:
            print(f"Scraper Warning: No results parsed. Content length: {len(html_content)}")
            # print(html_content[:500]) # Print start of content for debugging
                
        return results

    except Exception as e:
        print(f"Error scraping Baidu News: {e}")
        return []

def scrape_with_rule(url, rule):
    """
    Scrape content using a specific rule (xpath and headers).
    rule: dict containing 'title_xpath', 'content_xpath', 'headers' (dict or json str)
    """
    try:
        headers_raw = rule.get('headers', '{}')
        if isinstance(headers_raw, str):
            try:
                headers = json.loads(headers_raw)
            except:
                headers = {}
        else:
            headers = headers_raw if headers_raw else {}
        
        # Add default user-agent if missing
        if 'user-agent' not in {k.lower() for k in headers}:
            headers['User-Agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"

        response = requests.get(url, headers=headers, proxies={"http": None, "https": None}, timeout=10)
        response.encoding = response.apparent_encoding
        
        tree = html.fromstring(response.content)
        
        title = ""
        content = ""
        
        if rule.get('title_xpath'):
            titles = tree.xpath(rule['title_xpath'])
            if titles:
                # Handle various return types (Element, string, etc.)
                if hasattr(titles[0], 'text_content'):
                    title = titles[0].text_content().strip()
                else:
                    title = str(titles[0]).strip()
                
        if rule.get('content_xpath'):
            contents = tree.xpath(rule['content_xpath'])
            content_parts = []
            for c in contents:
                if hasattr(c, 'text_content'):
                    text = c.text_content().strip()
                else:
                    text = str(c).strip()
                if text:
                    content_parts.append(text)
            content = "\n".join(content_parts)
            
        return {'title': title, 'content': content}
        
    except Exception as e:
        print(f"Error scraping with rule for {url}: {e}")
        return None

def scrape_news_detail(url):
    """
    Deep scrape the content of a news page.
    Simple implementation: fetches page and extracts text from <p> tags.
    """
    headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0"
    }
    try:
        response = requests.get(url, headers=headers, proxies={"http": None, "https": None}, timeout=10)
        response.encoding = response.apparent_encoding # Try to detect encoding
        
        # Simple regex-based extraction to avoid heavy dependencies like BS4 if not available
        # Extract text between <p> and </p>
        html = response.text
        paragraphs = re.findall(r'<p.*?>(.*?)</p>', html, re.DOTALL | re.IGNORECASE)
        
        # Clean tags from paragraphs
        cleaned_text = []
        for p in paragraphs:
            # Remove inner tags
            text = re.sub(r'<.*?>', '', p).strip()
            if text:
                cleaned_text.append(text)
        
        return "\n".join(cleaned_text)
    except Exception as e:
        print(f"Error deep scraping {url}: {e}")
        return f"Error scraping content: {str(e)}"

if __name__ == "__main__":
    # Test the scraper
    keywords = "绵阳"
    news = scrape_baidu_news(keywords)
    print(f"Found {len(news)} news items for '{keywords}':")
    for item in news[:3]:
        print(item)
