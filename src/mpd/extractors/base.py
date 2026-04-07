import abc

class Extractor(abc.ABC):
    @abc.abstractmethod
    def extract(self, package: "Package") -> list[str]: ...
