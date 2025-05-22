#!/usr/bin/env python3
from settings import CertExtractorSettings
from classes import CertExtractor, Hooker

from watchdog.observers import Observer

import logging


if __name__ == "__main__":
  from sys import stdout

  logger = logging.getLogger()
  logger.setLevel(logging.DEBUG)
  handler = logging.StreamHandler(stdout)
  formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
  handler.setFormatter(formatter)
  logger.addHandler(handler)
  logger.debug('Cert extractor started')

  settings = CertExtractorSettings()
  ex = CertExtractor(settings, logger = logger)

  one_shot = False
  export_on_start = True
  run_hooks = True

  if run_hooks:
    ex.hook = Hooker(cert_dir=settings.output_dir, hook='../example-hook.sh')

  # Single shot mode
  if export_on_start or one_shot:
    if one_shot:
      logger.info(f"One-shot specified, will extract certs from {settings.input_file} and exit.")
    else:
      logger.info(f"Export on start specified, will extract certs from {settings.input_file} now before starting file observer.")

    updated_domains = ex.extract(check_hash=settings.check_hash)
    ex.hook(domains=updated_domains)
    logger.info(f"Updated domains: {','.join(updated_domains)}")

  if not one_shot:
    logger.debug(f"Start file watcher for {settings.input_file}")
    from time import sleep
    from classes import CertExtractor, FileUpdateHandler

    event_handler = FileUpdateHandler(ex, logger = logger)

    for changes in watch(settings.input_file):
        for change_type, file_path in changes:
            if change_type == Change.modified:
                with open(file_path) as f:
                    print(f.read())
            elif change_type == Change.added:
                print('File added, this is unexpected')
            elif change_type == Change.deleted:
                print('File deleted, this is unexpected')
            else:
                print(f"Unknown change type: {str(change_type)}")