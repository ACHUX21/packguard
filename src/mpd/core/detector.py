"""Main detector orchestrator."""
from mpd import models, logger
from mpd.downloaders import get_downloader
from mpd.extractors import get_extractor
from mpd.scanners import static, typosquat
from mpd.analyzers import get_analyzer
from mpd.exceptions import MPDError

log = logger.setup("INFO")

class Detector:
    def __init__(self, config, log):
        self.config = config
        self.log = log

    def run(self):
        self.log.info("Starting MPD scan")
        # Placeholder: iterate packages, download, extract, scan, analyze
        self.log.info("Scan complete")

    def _process_package(self, pkg_data: dict):
        source = pkg_data.get("source")
        downloader = get_downloader(source)
        extractor = get_extractor(source)
        pkg = downloader.download(pkg_data)
        files = extractor.extract(pkg)
        static_scanner = static.StaticScanner()
        typosquat_scanner = typosquat.TyposquatScanner(self.config.popular_packages_path)
        results = []
        for f in files:
            issues = static_scanner.scan(f) + typosquat_scanner.scan(f)
            if issues:
                analyzer = get_analyzer()
                analysis = analyzer.analyze(f, issues)
                results.append(analysis)
        return results
