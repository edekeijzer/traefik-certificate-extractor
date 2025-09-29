"""Settings classes"""
from pydantic import (
    RootModel,
    BaseModel,
    FilePath,
    DirectoryPath,
    HttpUrl,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

from typing import List, Optional
from enum import Enum


class AcmeAccountStatus(str, Enum):
    """Settings"""
    valid = "valid"
    deactivated = "deactivated"
    revoked = "revoked"


class KeyType(str, Enum):
    """Settings"""
    RSA2048 = "RSA2048"
    RSA3072 = "RSA3072"
    RSA4096 = "RSA4096"
    EC256 = "EC256"
    EC384 = "EC384"
    P256 = "P256"
    P384 = "P384"


class AcmeRegistrationBody(BaseModel):
    """Settings"""
    model_config = SettingsConfigDict()

    status: Optional[AcmeAccountStatus] = "valid"
    contact: Optional[List[str]] | None = None


class AcmeRegistration(BaseModel):
    """Settings"""
    model_config = SettingsConfigDict()

    body: AcmeRegistrationBody
    uri: Optional[HttpUrl]


class AcmeAccount(BaseSettings):
    """Settings"""
    model_config = SettingsConfigDict()

    # This should either be an EmailStr or empty string
    Email: Optional[str]
    Registration: AcmeRegistration
    PrivateKey: str
    KeyType: Optional[KeyType]

    @field_validator("Email")
    @classmethod
    def check_empty_email(cls, value):
        # Allow empty string and None
        if value == "":
            return None  # Treat empty string as None (or leave it as "")
        return value


class AcmeCertDomain(BaseSettings):
    """Settings"""
    model_config = SettingsConfigDict()

    main: str
    sans: List[str] = []


class AcmeCertificate(BaseSettings):
    """Settings"""
    model_config = SettingsConfigDict()

    domain: AcmeCertDomain
    certificate: str
    key: str
    Store: str = "default"


class AcmeResolver(BaseSettings):
    """Settings"""
    model_config = SettingsConfigDict()

    Account: AcmeAccount | None = None
    Certificates: List[AcmeCertificate] | None = None


# class AcmeSettings(BaseSettings):
#   model_config = SettingsConfigDict()


#   __root__: Dict[str, AcmeResolver]
class AcmeSettings(RootModel[dict[str, AcmeResolver]]):
    """Settings"""
    pass


class CertExtractorSettings(BaseSettings):
    """Settings"""
    model_config = SettingsConfigDict()

    input_file: FilePath = "/input/acme.json"
    output_dir: DirectoryPath = "/output"
    output_path_resolver: bool | None = None
    hook_dir: DirectoryPath = "/hooks"
    check_hash: bool = True
    oneshot: bool = False
    startup_extract: bool = True
    skip_wildcard: bool = True
    docker_command: bool = False
    docker_domain_label: Optional[str] = "traefik-certificate-extractor.domains"
    docker_command_label: Optional[str] = "traefik-certificate-extractor.command"

    @model_validator(mode="after")
    def check_mutual_exclusivity(self):
        if self.oneshot and not self.startup_extract:
            raise ValueError(
                f"Using 'oneshot: {self.oneshot}' implies extracting certificates at startup and exit, while 'startup_extract: {self.startup_extract}' implies you don't want to do anything at startup."
            )
        return self


# Hook settings class
class HookSettingsClass(BaseSettings):
    """Settings"""
    model_config = SettingsConfigDict()
