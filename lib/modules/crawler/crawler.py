from urllib.parse import urlparse

import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.linkextractors import LinkExtractor
from scrapy.spiders import CrawlSpider, Rule
from scrapy.utils.project import get_project_settings

from lib.utils.container import Services

urls = []


class SitadelSpider(CrawlSpider):
    name = "sitadel"

    rules = [
        Rule(
            LinkExtractor(
                canonicalize=True,
                unique=True
            ),
            follow=True,
            callback="parse_items"
        )
    ]

    # Method for parsing items
    def parse_items(self, response):
        links = LinkExtractor(canonicalize=True, unique=True).extract_links(response)
        for link in links:
            for allowed_domain in self.allowed_domains:
                if urlparse(link.url).netloc == allowed_domain:
                    urls.append(link.url)
                    yield scrapy.Request(link.url, callback=self.parse)


def crawl(url, user_agent):
    output = Services.get('output')

    # Settings for the crawler
    settings = get_project_settings()
    settings.set("USER_AGENT", user_agent)
    settings.set("LOG_LEVEL", "CRITICAL")

    # Create the process that will perform the crawl
    output.info('Start crawling the target website')
    process = CrawlerProcess(settings)
    domain = urlparse(url).hostname
    process.crawl(SitadelSpider, start_urls=[str(url)], allowed_domains=[str(domain)])
    process.start()

    # Clean the results
    clean_urls = []
    for u in urls:
        try:
            new_url = urlparse(u).geturl()
            if new_url not in clean_urls:
                clean_urls.append(new_url)
        except ValueError:
            continue

    return clean_urls
