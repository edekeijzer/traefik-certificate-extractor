from pydantic import RootModel, BaseModel, FilePath, DirectoryPath, EmailStr, HttpUrl, field_validator, model_validator, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from typing import List, Dict, Optional
from enum import Enum


class AcmeAccountStatus(str, Enum):
  valid = 'valid'
  deactivated = 'deactivated'
  revoked = 'revoked'


class KeyType(str, Enum):
  RSA2048 = 'RSA2048'
  RSA3072 = 'RSA3072'
  RSA4096 = 'RSA4096'
  EC256   = 'EC256'
  EC384   = 'EC384'
  P256    = 'P256'
  P384    = 'P384'


class AcmeRegistrationBody(BaseModel):
  model_config = SettingsConfigDict()

  status: Optional[AcmeAccountStatus] = 'valid'
  contact: Optional[List[str]] | None = None


class AcmeRegistration(BaseModel):
  model_config = SettingsConfigDict()

  body: AcmeRegistrationBody
  uri: Optional[HttpUrl]


class AcmeAccount(BaseSettings):
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
  model_config = SettingsConfigDict()

  main: str
  sans: List | None = None


class AcmeCertificate(BaseSettings):
  model_config = SettingsConfigDict()

  domain: AcmeCertDomain
  certificate: str
  key: str
  Store: str = 'default'


class AcmeResolver(BaseSettings):
  model_config = SettingsConfigDict()

  Account: AcmeAccount # Don't care about this but I have to map it accordingly
  Certificates: List[AcmeCertificate]


# class AcmeSettings(BaseSettings):
#   model_config = SettingsConfigDict()

#   __root__: Dict[str, AcmeResolver]
class AcmeSettings(RootModel[dict[str, AcmeResolver]]):
  pass


class CertExtractorSettings(BaseSettings):
  model_config = SettingsConfigDict()

  input_file: FilePath
  output_dir: DirectoryPath
  output_path_resolver: bool | None = None
  hook_dir: DirectoryPath = './hooks'
  check_hash: bool = True
  oneshot: bool = False
  startup_extract: bool = True
  docker_restart: bool = False
  docker_restart_label: Optional[str] = 'traefik-cert-extractor.restart-domains'

  @model_validator(mode='after')
  def check_mutual_exclusivity(self):
      if self.oneshot and not self.startup_extract:
          raise ValueError(f"Using 'oneshot: {self.oneshot}' implies extracting certificates at startup and exit, while 'startup_extract: {self.startup_extract}' implies you don't want to do anything at startup.")
      return self


# Hook settings class
class HookSettingsClass(BaseSettings):
  model_config = SettingsConfigDict()