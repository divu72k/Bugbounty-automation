import argparse
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse


class ScriptParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            return

        attrs = dict(attrs)
        src = attrs.get("src")

        if src:
            print(urljoin(self.base_url, src))


def main():
    parser = argparse.ArgumentParser(
        description="Extract JavaScript URLs from a local HTML file."
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="Target base URL, e.g. https://www.freshbus.com/"
    )

    parser.add_argument(
        "-f", "--file",
        default="js-analysis/page.html",
        help="Path to the downloaded HTML file (default: js-analysis/page.html)"
    )

    args = parser.parse_args()

    if urlparse(args.url).scheme not in ("http", "https") or not urlparse(args.url).netloc:
        parser.error("Please provide a valid HTTP or HTTPS URL.")

    base_url = args.url.rstrip("/") + "/"

    try:
        with open(args.file, encoding="utf-8") as html_file:
            html = html_file.read()
    except OSError as error:
        parser.error(f"Could not read HTML file: {error}")

    script_parser = ScriptParser(base_url)
    script_parser.feed(html)


if __name__ == "__main__":
    main()
