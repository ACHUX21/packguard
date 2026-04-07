import requests
from mpd.downloaders.base import Downloader
from mpd.models import Package

class PyPIDownloader(Downloader):
    def download(self, pkg_data: dict) -> Downloader:
        name = pkg_data["name"]
        url = f"https://pypi.org/pypi/{name}/json"
        resp = requests.get(url)
        resp.raise_for_status()
        data = resp.json()
        version = data["info"]["version"]
        return Package(name=name, version=version, source="pypi", url=url)
