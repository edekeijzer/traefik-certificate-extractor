"""Worker classes"""
# Standard imports
from abc import ABC, abstractmethod
from base64 import b64decode
from copy import deepcopy
import importlib.util
from inspect import getmembers, isclass
import logging
from os import system as os_system
from os.path import abspath
from pathlib import Path
from typing import List

# Third-party imports
from settings import AcmeSettings, CertExtractorSettings, HookSettingsClass


# Base class
class BaseClass(ABC):
    """Base class"""

    @abstractmethod
    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger(__name__)

    def __del__(self):
        self.logger.debug(f"Deleting {type(self).__name__} class")


# Simple stop event class
class StopEvent(BaseClass):
    """Stop event class"""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger(__name__)
        self._flag = False

    def set(self, flag: bool = True) -> None:
        """Function"""
        self._flag = flag
        self.logger.debug(f"Flag set to {str(flag)}")

    def is_set(self) -> bool:
        """Function"""
        return self._flag


# Hook base class
class HookBaseClass(ABC):
    """Hook base class"""

    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger(__name__)

    @abstractmethod
    def __call__(
        self, hook: str, cert_dir: str, logger: logging.Logger | None = None
    ) -> None:
        pass


# Shell script executor
class ShellHook(HookBaseClass):
    """Shell script hook class"""

    def __init__(
        self, hook: str, cert_dir: str, logger: logging.Logger | None = None
    ) -> None:
        super().__init__()
        self.hook = hook
        self.cert_dir = cert_dir

    def __call__(
        self,
        event: str,
        resolver: str = "",
        domains: List[str] | None = None,
        cert_dir: str | None = None,
        file_names: dict | None = None,
    ) -> None:
        self.logger.debug(f"Event: {event}")
        if domains:
            self.logger.debug(f"Domains: {','.join(domains)}")
        else:
            domains = []

        if not cert_dir:
            cert_dir = self.cert_dir

        cert_dir = abspath(cert_dir)

        for domain in domains:
            self.logger.info("Run %s for %s/%s", self.hook, cert_dir, domain)
            hook_cmd = f"{self.hook} {event} {cert_dir} {domain} {cert_dir}"
            if file_names is not None:
                hook_cmd = f"{hook_cmd} {file_names['privkey']} {file_names['cert']} {file_names['fullchain']} {file_names['chain']} {file_names['combined']}"
            hook_out = os_system(hook_cmd)
            if hook_out == 0:
                self.logger.debug("%s completed successfully for %s", self.hook, domain)
            else:
                self.logger.warning("%s returned %s for %s", self.hook, hook_out, domain)


# Build docker logic here
class DockerHook(HookBaseClass):
    """Docker hook class"""

    def __init__(
        self,
        domain_label: str = "traefik-certificate-extractor.domains",
        command_label: str = "traefik-certificate-extractor.command",
        logger: logging.Logger | None = None,
    ) -> None:
        super().__init__()
        from docker import from_env as docker_from_env

        self.client = docker_from_env()
        self.domain_label = domain_label
        self.command_label = command_label

    def __call__(
        self,
        event: str,
        resolver: str = "",
        domains: List[str] | None = None,
        cert_dir: str | None = None,
        file_names: dict | None = None,
    ) -> bool:

        if not domains:
            domains = []

        self.logger.debug("DockerHook fired, event: %s, resolver: %s, domains: %s", event, resolver, ','.join(domains))
        great_success = True
        if event == "update":
            containers = self.client.containers.list(
                filters={"label": self.domain_label}
            )
            self.logger.debug("Found %i containers with label %s", len(containers), self.domain_label)
            for container in containers:
                container_domains = str.split(container.labels[self.domain_label], ",")
                if self.command_label in container.labels:
                    _command = container.labels[self.command_label]
                else:
                    _command = None

                self.logger.debug("Found %i domains for container %s: %s", len(container_domains), container.name, container.labels[self.domain_label])
                if not set(domains).isdisjoint(container_domains):
                    try:
                        if _command and _command in ["SIGHUP", "SIGINT"]:
                            container.kill(signal=_command)
                            self.logger.info("Executed docker kill %s for container: %s (%s)", _command, container.name, container.id)
                        elif _command:
                            container.exec_run(
                                cmd=_command,
                                stdout=True,
                                stderr=True,
                                stdin=True,
                                tty=True,
                            )
                            self.logger.info(
                                "Executed command %s in container: %s (%s)", _command, container.name, container.id)
                        else:
                            container.restart()
                            self.logger.info("Restarted container: %s (%s)", container.name, container.id)
                    except:
                        great_success = False
                        self.logger.error("Error processing container: %s", container.id)


class CertExtractor(BaseClass):
    """Cert Extractor class"""

    def __init__(
        self, settings: CertExtractorSettings, logger: logging.Logger | None = None
    ) -> None:
        self.logger = logger or logging.getLogger(__name__)
        self.input_file = settings.input_file
        self.output_dir = settings.output_dir
        self.output_path_resolver = settings.output_path_resolver
        self.check_hash = settings.check_hash
        self.skip_wildcard = settings.skip_wildcard
        self.hook_dir = settings.hook_dir
        self.hooks: List[callable] = []

        if settings.docker_domain_label:
            self.logger.debug(
                f"Add DockerHook with label {settings.docker_domain_label}"
            )
            _hook = DockerHook(domain_label=settings.docker_domain_label, logger=logger)
            self.hooks.append(_hook)

        with Path(self.hook_dir) as hook_dir:
            for hook in hook_dir.glob("*.sh"):
                self.logger.debug(f"Adding hook: {hook}")
                _hook = ShellHook(
                    hook=hook, cert_dir=self.output_dir, logger=self.logger
                )
                self.hooks.append(_hook)

        for hook_file in hook_dir.glob("*.py"):
            self.logger.debug("Inspecting: %s", hook_file.name)
            # Make another class out of this
            module = self.load_module_from_file(hook_file)
            for hook_class in self.get_classes_from_module(module):
                self.logger.debug("Found class: %s", hook_class.__name__)

                if self.is_callable_with_args(
                    hook_class, {"event", "cert_dir", "resolver", "domains"}
                ):
                    self.logger.debug("Adding %s to hooks", hook_class.__name__)
                    self.hooks.append(hook_class(logger=self.logger))
                else:
                    self.logger.debug("Skipping %s: no __call__(hook, cert_dir, resolver, domains)", hook_class.__name__)

    def load_module_from_file(self, file_path):
        """Load python module from file"""
        module_name = Path(file_path).stem
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def get_classes_from_module(self, module):
        """Get classes from python module"""
        return [
            obj
            for name, obj in getmembers(module, isclass)
            if obj.__module__ == module.__name__
            and (issubclass(obj, HookBaseClass) or issubclass(obj, HookSettingsClass))
        ]

    def is_callable_with_args(self, cls, required_args):
        """Is class callable with required arguments"""
        if not hasattr(cls, "__call__"):
            return False
        from inspect import signature

        call_method = getattr(cls, "__call__")
        sig = signature(call_method)
        params = list(sig.parameters.values())[1:]  # skip `self`

        param_names = {param.name for param in params}
        return all(arg in param_names for arg in required_args)

    def watch(self, stop_event: StopEvent | None) -> None:
        """Watch file until stop event"""
        from watchfiles import watch, Change

        for changes in watch(self.input_file, debug=False, stop_event=stop_event):
            for change_type, file_path in changes:
                if change_type == Change.modified:
                    self.logger.info("File %s was modified", file_path)
                    self.extract(check_hash=self.check_hash)
                elif change_type == Change.added:
                    self.logger.warning("File %s was added, this is unexpected", file_path)
                elif change_type == Change.deleted:
                    self.logger.warning("File %s was deleted, this is unexpected", file_path)
                else:
                    self.logger.error("Unknown change type: %s", str(change_type))

    def extract(self, check_hash: bool | None = None) -> List[str]:
        """Extract certificates from json"""
        self.hook(event="pre", domains=[])
        if check_hash is None:
            check_hash = self.check_hash
        self.logger.info("Extraction, check_hash = %s", check_hash)

        updated_domains = list()

        with open(self.input_file, "r") as input_file:
            cert_data = AcmeSettings.model_validate_json(input_file.read()).root
            # Traefik v2/v3 acme.json is a dict of cert-resolvers
            if self.output_path_resolver is None:
                if len(cert_data) > 1:
                    self.output_path_resolver = True
                else:
                    self.output_path_resolver = False
                self.logger.debug("Found %i resolvers and output_path_resolver not set, defaulting to %s", len(cert_data), str(self.output_path_resolver))
            for resolver_name in cert_data.keys():
                resolver_data = cert_data[resolver_name]
                self.logger.info("Parsing cert resolver: %s", resolver_name)
                # resolver_data = cert_data[cert_resolver]
                # resolver_data = AcmeResolver(**resolver_data)
                # Each resolver has Account and Certificates data, unless it isn't used.
                certificates = resolver_data.Certificates
                if certificates is None:
                    continue

                for cert in certificates:
                    # Reset this for each cert/domain. Do I need to deepcopy this?
                    _hash_check = deepcopy(check_hash)
                    domain = cert.domain.main
                    sans = cert.domain.sans

                    if domain.startswith('*.') and self.skip_wildcard:
                        self.logger.debug("Skipping wildcard domain")
                        continue

                    self.logger.info("Cert domain: %s; SANs: %s", domain, ','.join(sans))
                    self.hook(
                        event="pre-cert",
                        resolver=resolver_name,
                        domains=([domain] + sans),
                    )

                    privkey = b64decode(cert.key).decode("utf-8")
                    fullchain = b64decode(cert.certificate).decode("utf-8")

                    _dir = Path(f"{self.output_dir}/{resolver_name}/{domain}")
                    _privkey_path = _dir.joinpath("privkey.pem")
                    _cert_path = _dir.joinpath("cert.pem")
                    _chain_path = _dir.joinpath("chain.pem")
                    _fullchain_path = _dir.joinpath("fullchain.pem")
                    _combined_path = _dir.joinpath("combined.pem")

                    if not _dir.exists():
                        self.logger.info("Creating non-existent directory %s", _dir)
                        _dir.mkdir(parents=True, exist_ok=True)
                        _hash_check = False

                    # Touch these so they always exist when trying to open for read/write
                    _privkey_path.touch()
                    _fullchain_path.touch()

                    with open(_privkey_path, "r+") as file:
                        if not (_hash_check and file.read() == privkey):
                            self.logger.debug("Write privkey.pem")
                            file.seek(0)
                            file.write(privkey)
                            file.truncate()
                            _hash_check = False
                    with open(_fullchain_path, "r+") as file:
                        if not (_hash_check and file.read() == fullchain):
                            self.logger.debug("Write fullchain.pem")
                            file.seek(0)
                            file.write(fullchain)
                            file.truncate()
                            _hash_check = False
                    # If the fullchain did not change, its derivates can't possibly have changed
                    if not _hash_check:
                        # Split full chain into our cert and the CA chain
                        _start = fullchain.find("-----BEGIN CERTIFICATE-----", 1)
                        cert = fullchain[0:_start]
                        chain = fullchain[_start:]

                        with open(_cert_path, "w") as file:
                            self.logger.debug("Write cert.pem")
                            file.write(cert)
                        with open(_chain_path, "w") as file:
                            self.logger.debug("Write chain.pem")
                            file.write(chain)
                        with open(_combined_path, "w") as file:
                            self.logger.debug("Write combined.pem")
                            file.write(privkey)
                            file.write(cert)

                    if not _hash_check:
                        self.logger.info("Add domain %s to updated domains", domain)
                        updated_domains.append(domain)
                        _file_names = dict(
                            privkey=str(_privkey_path),
                            cert=str(_cert_path),
                            chain=str(_chain_path),
                            fullchain=str(_fullchain_path),
                            combined=str(_combined_path),
                        )
                        self.hook(
                            event="update",
                            resolver=resolver_name,
                            domains=([domain] + sans),
                            cert_dir=_dir,
                            file_names=_file_names,
                        )
                    else:
                        self.logger.info("Domain %s was not updated", domain)

        self.hook(event="post")
        return updated_domains

    # Hook invocation
    def hook(
        self,
        event: str,
        resolver: str = "",
        domains: List[str] | None = None,
        cert_dir: str | None = None,
        file_names: dict | None = None,
    ) -> None:
        """Hook invocator"""

        if domains is None:
            domains = []

        self.logger.debug(f"Number of hooks: {len(self.hooks)}")
        for hook in self.hooks:
            hook(
                event=event,
                resolver=resolver,
                domains=domains,
                cert_dir=cert_dir,
                file_names=file_names,
            )
