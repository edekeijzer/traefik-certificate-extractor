from settings import AcmeSettings, CertExtractorSettings, HookSettingsClass
from typing import List
from pathlib import Path
from base64 import b64decode
from copy import deepcopy
import logging
from abc import ABC, abstractmethod


# Base class
class BaseClass(ABC):
  @abstractmethod
  def __init__(self, logger: logging.Logger | None = None) -> None:
    self.logger = logger or logging.getLogger(__name__)

  def __del__(self):
    self.logger.debug(f"Deleting {type(self).__name__} class")


# Simple stop event class
class StopEvent(BaseClass):
  def __init__(self, logger: logging.Logger | None = None) -> None:
    self.logger = logger or logging.getLogger(__name__)
    self._flag = False

  def set(self, flag: bool = True) -> None:
    self._flag = flag
    self.logger.debug(f"Flag set to {str(flag)}")

  def is_set(self) -> bool:
    return self._flag


# Hook base class
class HookBaseClass(ABC):
  def __init__(self, logger: logging.Logger | None = None) -> None:
    self.logger = logger or logging.getLogger(__name__)

  @abstractmethod
  def __call__(self, hook: str, cert_dir: str, logger: logging.Logger | None = None) -> None:
    pass


# Shell script executor
class ShellHook(HookBaseClass):
  def __init__(self, hook: str, cert_dir: str, logger: logging.Logger | None = None) -> None:
    self.logger = logger or logging.getLogger(__name__)
    self.hook = hook
    self.cert_dir = cert_dir

  def __call__(self, event: str, resolver: str = '', domains: List[str] = [], cert_dir: str | None = None, file_names: dict | None = None) -> None:
    self.logger.debug(f"Event: {event}")
    if domains: self.logger.debug(f"Domains: {','.join(domains)}")

    from os import system as os_system
    from os.path import abspath as os_abspath
    if not cert_dir:
      cert_dir = self.cert_dir

    cert_dir = os_abspath(cert_dir)

    for domain in domains:
      self.logger.info(f"Run {self.hook} for {cert_dir}/{domain}")
      hook_out = os_system(f"{self.hook} {cert_dir} {domain}")
      if hook_out == 0:
        self.logger.debug(f"{self.hook} completed successfully for {cert_dir}/{domain}")
      else:
        self.logger.warning(f"{self.hook} returned {hook_out} for {cert_dir}/{domain}")


# Build docker logic here
class DockerHook(HookBaseClass):
  def __init__(self, restart_label: str = 'traefik-cert-extractor.restart-domains', logger: logging.Logger | None = None) -> None:
    self.logger = logger or logging.getLogger(__name__)
    from docker import from_env as docker_from_env
    self.client = docker_from_env()
    self.restart_label = restart_label

  def __call__(self, event: str, resolver: str = '', domains: List[str] = [], cert_dir: str | None = None, file_names: dict | None = None) -> bool:
    self.logger.debug(f"DockerHook fired, event: {event}, resolver: {resolver}, domains: {','.join(domains)}")
    great_success = True
    if (event == 'update'):
      containers = self.client.containers.list(filters = {'label' : self.restart_label})
      self.logger.debug(f"Found {len(containers)} containers with label {self.restart_label}")
      for container in containers:
        container_domains = str.split(container.labels[self.restart_label], ',')

        self.logger.debug(f"Found {len(container_domains)} domains for container '{container.name}: {container.labels[self.restart_label]}")
        if not set(domains).isdisjoint(container_domains):
          self.logger.info(f"Restarting container: {container.name} ({container.id})")
        try:
          container.restart()
        except:
          great_success = False
          self.logger.error(f"Error restarting container: {container.id}")


class CertExtractor(BaseClass):
  def __init__(self, settings: CertExtractorSettings, logger: logging.Logger | None = None) -> None:
    self.logger = logger or logging.getLogger(__name__)
    self.input_file = settings.input_file
    self.output_dir = settings.output_dir
    self.output_path_resolver = settings.output_path_resolver
    self.check_hash = settings.check_hash
    self.hook_dir = settings.hook_dir
    self.hooks: List[callable] = []

    if settings.docker_restart_label:
      self.logger.debug(f"Add DockerHook with label {settings.docker_restart_label}")
      _hook = DockerHook(restart_label=settings.docker_restart_label, logger=logger)
      self.hooks.append(_hook)

    with Path(self.hook_dir) as hook_dir:
      for hook in hook_dir.glob('*.sh'):
        self.logger.debug(f"Adding hook: {hook}")
        _hook = ShellHook(hook=hook, cert_dir=self.output_dir, logger=self.logger)
        self.hooks.append(_hook)

    for hook_file in hook_dir.glob('*.py'):
      self.logger.debug(f"Inspecting: {hook.name}")
      # Make another class out of this
      module = self.load_module_from_file(hook_file)
      classes = self.get_classes_from_module(module)
      for hook_class in self.get_classes_from_module(module):
        self.logger.debug(f"Found class: {hook_class.__name__}")

        if self.is_callable_with_args(hook_class, {'event', 'cert_dir', 'resolver', 'domains'}):
          self.logger.debug(f"Adding {hook_class.__name__} to hooks")
          self.hooks.append(hook_class(logger=self.logger))
        else:
          self.logger.debug(f"Skipping {hook_class.__name__}: no __call__(hook, cert_dir, resolver, domains)")

    if logger:
      self.log_debug = logger.debug
      self.log_info = logger.info
      self.log_warning = logger.warning
      self.log_error = logger.error
      self.log_critical = logger.critical
    else:
      self.log_debug = self.log
      self.log_info = self.log
      self.log_warning = self.log
      self.log_error = self.log
      self.log_critical = self.log


  def load_module_from_file(self, file_path):
    import importlib.util

    module_name = Path(file_path).stem
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


  def get_classes_from_module(self, module):
    from inspect import getmembers, isclass
    return [
      obj for name, obj in getmembers(module, isclass)
      if obj.__module__ == module.__name__ and (issubclass(obj, HookBaseClass) or issubclass(obj, HookSettingsClass))
    ]


  def is_callable_with_args(self, cls, required_args):
    if not hasattr(cls, '__call__'):
        return False
    from inspect import signature
    call_method = getattr(cls, '__call__')
    sig = signature(call_method)
    params = list(sig.parameters.values())[1:]  # skip `self`

    param_names = {param.name for param in params}
    return all(arg in param_names for arg in required_args)


  def log(self, msg: str):
    print(msg)


  def watch(self, stop_event: StopEvent | None) -> None:
    from watchfiles import watch, Change
    for changes in watch(self.input_file, debug=False, stop_event=stop_event):
      for change_type, file_path in changes:
        if change_type == Change.modified:
          self.log_info(f"File {file_path} was modified")
          self.extract(check_hash=self.check_hash)
        elif change_type == Change.added:
          self.log_warning(f"File {file_path} was added, this is unexpected")
        elif change_type == Change.deleted:
          self.log_warning(f"File {file_path} was deleted, this is unexpected")
        else:
          self.log_error(f"Unknown change type: {str(change_type)}")


  def extract(self, check_hash: bool | None = None) -> List[str]:
    self.hook(event='pre', domains=[])
    if check_hash is None:
      check_hash = self.check_hash
    self.log_info(f"Extraction, check_hash = {check_hash}")
    from json import load as json_load

    updated_domains = list()

    with open(self.input_file, 'r') as input_file:
      cert_data = AcmeSettings.model_validate_json(input_file.read()).root
      # Traefik v2/v3 acme.json is a dict of cert-resolvers
      if self.output_path_resolver is None:
        if len(cert_data) > 1:
          self.output_path_resolver = True
        else:
          self.output_path_resolver = False
        self.log_debug(f"Found {str(len(cert_data))} resolvers and output_path_resolver not set, defaulting to {str(self.output_path_resolver)}")
      for resolver_name in cert_data.keys():
        resolver_data = cert_data[resolver_name]
        self.log_info(f"Parsing cert resolver: {resolver_name}")
        # resolver_data = cert_data[cert_resolver]
        # resolver_data = AcmeResolver(**resolver_data)
        # Each resolver has Account and Certificates data
        certificates = resolver_data.Certificates

        for cert in certificates:
          # Reset this for each cert/domain. Do I need to deepcopy this?
          _hash_check = deepcopy(check_hash)
          domain = cert.domain.main
          sans = cert.domain.sans
          self.log_info(f"Cert domain: {domain}; SANs: {','.join(sans)}")
          self.hook(event='pre-cert', resolver=resolver_name, domains=([domain] + sans))

          privkey = b64decode(cert.key).decode('utf-8')
          fullchain = b64decode(cert.certificate).decode('utf-8')

          _dir = Path(f"{self.output_dir}/{resolver_name}/{domain}")
          _privkey_path = _dir.joinpath('privkey.pem')
          _cert_path = _dir.joinpath('cert.pem')
          _chain_path = _dir.joinpath('chain.pem')
          _fullchain_path = _dir.joinpath('fullchain.pem')

          if not _dir.exists():
            self.log_info(f"Creating non-existent directory {_dir}")
            _dir.mkdir(parents=True, exist_ok=True)
            _hash_check = False

          # Touch these so they always exist when trying to open for read/write
          _privkey_path.touch()
          _fullchain_path.touch()

          with open(_privkey_path, 'r+') as file:
            if not (_hash_check and file.read() == privkey):
              self.log_debug('Write privkey.pem')
              file.seek(0)
              file.write(privkey)
              file.truncate()
              _hash_check = False
          with open(_fullchain_path, 'r+') as file:
            if not (_hash_check and file.read() == fullchain):
              self.log_debug('Write fullchain.pem')
              file.seek(0)
              file.write(fullchain)
              file.truncate()
              _hash_check = False
          # If the fullchain did not change, its derivates can't possibly have changed
          if not _hash_check:
            # Split full chain into our cert and the CA chain
            _start = fullchain.find('-----BEGIN CERTIFICATE-----', 1)
            cert = fullchain[0:_start]
            chain = fullchain[_start:]

            with open(_cert_path, 'w') as file:
              self.log_debug('Write cert.pem')
              file.write(cert)
            with open(_chain_path, 'w') as file:
              self.log_debug('Write chain.pem')
              file.write(chain)

          if not _hash_check:
            self.log_info(f"Add domain {domain} to updated domains")
            updated_domains.append(domain)
            _file_names = dict(
              privkey = str(_privkey_path),
              cert = str(_cert_path),
              chain = str(_chain_path),
              fullchain = str(_fullchain_path),
            )
            self.hook(event='update', resolver=resolver_name, domains=([domain] + sans), cert_dir=_dir, file_names=_file_names)
          else:
            self.log_info(f"Domain {domain} was not updated")

    self.hook(event='post')
    return updated_domains


  # Hook invocation
  def hook(self, event: str, resolver: str = '', domains: List[str] = [], cert_dir: str | None = None, file_names: dict | None = None) -> None:
    self.log_debug(f"Number of hooks: {len(self.hooks)}")
    for hook in self.hooks:
      hook(event=event, resolver=resolver, domains=domains, cert_dir=cert_dir, file_names=file_names)