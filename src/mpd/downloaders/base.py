import abc

class Downloader(abc.ABC):
    @abc.abstractmethod
    def download(self, pkg_data: dict) -> "Package": ...
