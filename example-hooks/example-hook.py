from classes import HookBaseClass
from settings import HookSettingsClass
import logging

class example_hook(HookBaseClass):
  def __call__(self, event: str, cert_dir: str, resolver: str, domains: list[str] = [], file_names: dict | None = None) -> None:
    self.logger.debug(f"example_hook: event = {event}")
    self.logger.debug(f"example_hook: cert_dir = {cert_dir}")
    self.logger.debug(f"example_hook: resolver = {resolver}")
    self.logger.debug(f"example_hook: domains = {domains}")
    self.logger.debug(f"example_hook: file_names = {file_names}")
    if event == 'update':
      with open(file_names['cert'], 'r') as input_file:
        print(input_file.read())

class settings_helper(HookSettingsClass):
  def __init__(self):
    pass