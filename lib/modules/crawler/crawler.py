from urllib.parse import urlparse

from scrapy.crawler import CrawlerProcess
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
from scrapy.utils.project import get_project_settings

from lib.utils.container import Services

urls = set()
allowed_domains = []


class SitadelSpider(CrawlSpider):
    name = "sitadel"

    rules = [
        Rule(
            LinkExtractor(canonicalize=True, unique=True),
            follow=True,
            process_links="parse_items",
        )
    ]

    # Method for parsing items
    @classmethod
    def parse_items(cls, links):
        for link in links:
            if urlparse(link.url).netloc in allowed_domains:
                urls.add(link.url)
                yield link

def crawl(url, user_agent):
    try:
        output = Services.get("output")

        # Settings for the crawler
        settings = get_project_settings()
        settings.set("USER_AGENT", user_agent)
        settings.set("LOG_LEVEL", "CRITICAL")
        settings.set("RETRY_ENABLED", False)
        settings.set("CONCURRENT_REQUESTS", 15)

        # Create the process that will perform the crawl
        output.info("Start crawling the target website")
        process = CrawlerProcess(settings)
        allowed_domains.append(str(urlparse(url).hostname))
        process.crawl(
            SitadelSpider, start_urls=[str(url)], allowed_domains=allowed_domains
        )
        process.start()

        # Clean the results
        clean_urls = []
        for u in urls:
            try:
                new_url = urlparse(u).geturl()
                clean_urls.append(new_url)
            except ValueError:
                continue
        return clean_urls

    except KeyboardInterrupt:
        process.stop()
        raise

