#!/usr/bin/env python3
from os import path as os_path, system as os_system
from settings import CertExtractorSettings, AcmeSettings
from classes import CertExtractor, DockerHook
import logging

if __name__ == '__main__':
  from sys import stdout

  logger = logging.getLogger('traefik-certificate-extractor')
  logger.setLevel(logging.DEBUG)
  handler = logging.StreamHandler(stdout)
  formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
  handler.setFormatter(formatter)
  logger.addHandler(handler)
  logger.debug('Cert extractor started')

  settings = CertExtractorSettings()

  try:
    logger.info(f"Start watching {settings.input_file}")
    logging.getLogger('watchfiles').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    ex = CertExtractor(settings=settings, logger=logger)
    if settings.docker_restart:
      ex.hooks.append(DockerHook(logger=logger))
    if settings.startup_extract or settings.oneshot:
      ex.extract()
    if not settings.oneshot:
      from classes import StopEvent
      stop_event = StopEvent(logger=logger)
      ex.watch(stop_event=stop_event)

  except KeyboardInterrupt:
    stop_event.set()
    exit(0)