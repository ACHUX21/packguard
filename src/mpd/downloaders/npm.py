import requests
from mpd.downloaders.base import Downloader
from mpd.models import Package

class NpmDownloader(Downloader):
    def download(self, pkg_data: dict) -> Package:
        name = pkg_data["name"]
        url = f"https://registry.npmjs.org/{name}"
        resp = requests.get(url)
        resp.raise_for_status()
        data = resp.json()
        # simplified: create a Package with placeholder
        return Package(name=name, version="latest", source="npm", url=url)
