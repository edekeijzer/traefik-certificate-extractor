#!/usr/bin/env python3
import logging
from sys import stdout, exit as sys_exit

from settings import CertExtractorSettings
from classes import CertExtractor, DockerHook

if __name__ == "__main__":

    logger = logging.getLogger("traefik-certificate-extractor")
    logger.setLevel(logging.DEBUG)
    handler = logging.StreamHandler(stdout)
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.debug("Cert extractor started")

    settings = CertExtractorSettings()

    try:
        logger.info("Start watching %s", settings.input_file)
        logging.getLogger("watchfiles").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        ex = CertExtractor(settings=settings, logger=logger)
        if settings.docker_command:
            ex.hooks.append(DockerHook(logger=logger))
        if settings.startup_extract or settings.oneshot:
            ex.extract()
        if not settings.oneshot:
            from classes import StopEvent

            stop_event = StopEvent(logger=logger)
            ex.watch(stop_event=stop_event)

    except KeyboardInterrupt:
        stop_event.set()
        sys_exit(0)
