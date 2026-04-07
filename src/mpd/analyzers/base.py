import abc

class Analyzer(abc.ABC):
    @abc.abstractmethod
    def analyze(self, file_path: str, issues: list) -> dict: ...
