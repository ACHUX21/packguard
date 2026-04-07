import zipfile
import tarfile
import os
from mpd.extractors.base import Extractor

class PyPIExtractor(Extractor):
    def extract(self, package):
        files = []
        # Placeholder: download wheel, extract, list files
        return files
