import sys
import errno
import time
import threading
import argparse
# import docker
from argparse import ArgumentTypeError as err
from os import path as os_path, system as os_system
from docker import from_env as docker_from_env
from base64 import b64decode
from json import loads as json_loads
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path
from hashlib import sha1

class PathType(object):
    def __init__(self, exists=True, type='file', dash_ok=True):
        '''exists:
                True: a path that does exist
                False: a path that does not exist, in a valid parent directory
                None: don't care
           type: file, dir, symlink, None, or a function returning True for valid paths
                None: don't care
           dash_ok: whether to allow "-" as stdin/stdout'''

        assert exists in (True, False, None)
        assert type in ('file', 'dir', 'symlink',
                        None) or hasattr(type, '__call__')

        self._exists = exists
        self._type = type
        self._dash_ok = dash_ok

    def __call__(self, string):
        if string == '-':
            # the special argument "-" means sys.{in,out}
            if self._type == 'dir':
                raise err(
                    'standard input/output (-) not allowed as directory path')
            elif self._type == 'symlink':
                raise err(
                    'standard input/output (-) not allowed as symlink path')
            elif not self._dash_ok:
                raise err('standard input/output (-) not allowed')
        else:
            e = os_path.exists(string)
            if self._exists == True:
                if not e:
                    raise err("path does not exist: '%s'" % string)

                if self._type is None:
                    pass
                elif self._type == 'file':
                    if not os_path.isfile(string):
                        raise err("path is not a file: '%s'" % string)
                elif self._type == 'symlink':
                    if not os_path.symlink(string):
                        raise err("path is not a symlink: '%s'" % string)
                elif self._type == 'dir':
                    if not os_path.isdir(string):
                        raise err("path is not a directory: '%s'" % string)
                elif not self._type(string):
                    raise err("path not valid: '%s'" % string)
            else:
                if self._exists == False and e:
                    raise err("path exists: '%s'" % string)

                p = os_path.dirname(os_path.normpath(string)) or '.'
                if not os_path.isdir(p):
                    raise err("parent path is not a directory: '%s'" % p)
                elif not os_path.exists(p):
                    raise err("parent directory does not exist: '%s'" % p)

        return string

class Handler(FileSystemEventHandler):

    def __init__(self, args):
        self.args = args
        self.isWaiting = False
        self.timer = threading.Timer(0.5, self.doTheWork)
        self.lock = threading.Lock()

    def on_created(self, event):
        self.handle(event)

    def on_modified(self, event):
        self.handle(event)

    def handle(self, event):
        # Check if it's a JSON file
        print('DEBUG : event fired')
        if not event.is_directory and event.src_path.endswith(str(self.args.certificate)):
            print('Certificates changed')

            with self.lock:
                if not self.isWaiting:
                    self.isWaiting = True #trigger the work just once (multiple events get fired)
                    self.timer = threading.Timer(2, self.doTheWork)
                    self.timer.start()

    def restartContainerWithDomains(self, domains):
        client = docker_from_env()
        container = client.containers.list(filters = {"label" : self.args.restart_container_label})
        for c in container:
            restartDomains = str.split(c.labels[self.args.restart_container_label], ',')
            if not set(domains).isdisjoint(restartDomains):
                print('restarting container ' + c.id)
                if not self.args.dry:
                    c.restart()

    def createCerts(self):
        # Read JSON file
        data = json_loads(open(self.args.certificate).read())

        # Determine Traefik version, extract data dictonary
        key = 'Account'
        if not key in data:
            root_key = list(data.keys())[0]
            data = data[root_key]
            traefik_version = 2
        else:
            traefik_version = 1

        # Determine ACME version
        acme_version = 2 if 'acme-v02' in data['Account']['Registration']['uri'] else 1

        # Find certificates
        if acme_version == 1:
            certs = data['DomainsCertificate']['Certs']
        elif acme_version == 2:
            certs = data['Certificates']

        # Loop over all certificates
        names = []

        for c in certs:
            if acme_version == 1:
                name = c['Certificate']['Domain']
                privatekey = c['Certificate']['PrivateKey']
                fullchain = c['Certificate']['Certificate']
                sans = c['Domains']['SANs']
            elif acme_version == 2 and traefik_version == 1:
                name = c['Domain']['Main']
                privatekey = c['Key']
                fullchain = c['Certificate']
                sans = c['Domain']['SANs']
            elif acme_version and traefik_version == 2:
                name = c['domain']['main']
                privatekey = c['key']
                fullchain = c['certificate']
                if 'sans' in c['domain']:
                    sans = c['domain']['sans']
                else:
                    sans = None

            if (self.args.include and name not in self.args.include) or (self.args.exclude and name in self.args.exclude):
                continue

            directory = Path(self.args.directory)

            if self.args.flat:
                self.doHook(f"pre_cert_flat {name} {directory}")
            else:
                self.doHook(f"pre_cert {name} {directory / name}")

            # Decode private key, certificate and chain
            privatekey = b64decode(privatekey).decode('utf-8')
            fullchain = b64decode(fullchain).decode('utf-8')
            start = fullchain.find('-----BEGIN CERTIFICATE-----', 1)
            cert = fullchain[0:start]
            chain = fullchain[start:]

            if not self.args.dry:
                files_changed = False
                # Create domain     directory if it doesn't exist
                if not directory.exists():
                    directory.mkdir()

                if self.args.flat:
                    privatekey_file = f"{directory}/{name}.key"
                    fullchain_file = f"{directory}/{name}.crt"
                    chain_file = f"{directory}/{name}.chain.pem"
                    # Write private key, certificate and chain to flat files

                    # if sans:
                    #     for name in sans:
                    #         with (directory / (name + '.key')).open('w') as f:
                    #             f.write(privatekey)
                    #         with (directory / (name + '.crt')).open('w') as f:
                    #             f.write(fullchain)
                    #         with (directory / (name + '.chain.pem')).open('w') as f:
                    #             f.write(chain)
                else:
                    directory = directory / name
                    if not directory.exists():
                        print(f"DEBUG : Create dir: {directory}")
                        directory.mkdir()

                    privatekey_file = f"{directory}/privkey.pem"
                    cert_file = f"{directory}/cert.pem"
                    fullchain_file = f"{directory}/fullchain.pem"
                    combined_file = f"{directory}/combined.pem"
                    chain_file = f"{directory}/chain.pem"

                    if not self.checkHash(fullchain, fullchain_file):
                        files_changed = True
                        with (fullchain_file).open('w') as f:
                            f.write(fullchain)
                    else:
                        print(f"Hash not changed for {fullchain_file}")

                    if not self.checkHash(privatekey, privatekey_file):
                        files_changed = True
                        # Write private key, certificate and chain to file
                        with (privatekey_file).open('w') as f:
                            f.write(privatekey)
                    else:
                        print(f"Hash not changed for {privatekey_file}")

                    if not self.checkHash(chain, chain_file):
                        files_changed = True
                        with (chain_file).open('w') as f:
                            f.write(chain)
                    else:
                        print(f"Hash not changed for {chain_file}")

                    if not self.args.flat:
                        if not self.checkHash(cert, cert_file):
                            files_changed = True
                            with (cert_file).open('w') as f:
                                f.write(cert)
                        else:
                            print(f"Hash not changed for {cert_file}")

                        combined_data = privatekey + cert
                        if not self.checkHash(combined_data, combined_file):
                            files_changed = True
                            with (combined_file).open('w') as f:
                                f.write(combined_data)
                        else:
                            print(f"Hash not changed for {combined_file}")

            print('Extracted certificate for: ' + name +
                (', ' + ', '.join(sans) if sans else ''))
            names.append(name)

            if files_changed:
                if args.flat:
                    self.doHook(f"post_cert_flat {name} {directory}")
                else:
                    self.doHook(f"post_cert {name} {directory}")
            else:
              print("Files not changed, skipping hooks")

        return names

    def checkHash(self, data, filepath):
        if not os_path.exists(filepath):
            return False
        with open(filepath, 'r') as f:
            file_data = f.read()
            hasher = sha1()
            hasher.update(file_data.encode('ascii'))
            file_hash = hasher.hexdigest()
            hasher = sha1()
            hasher.update(data.encode('ascii'))
            data_hash = hasher.hexdigest()
        return data_hash == file_hash

    def doTheWork(self):
        print('DEBUG : starting the work')
        self.doHook('pre_run')
        domains = self.createCerts()
        if (self.args.restart_container):
            print(f"DEBUG : restart containers tagged with label {self.args.restart_container_label}")
            self.restartContainerWithDomains(domains)

        with self.lock:
            self.isWaiting = False

        self.doHook('post_run')
        print('DEBUG : finished')

    def doHook(self, hook_args):
        if self.args.hook:
            hook_out = os_system(f"{self.args.hook} {hook_args}")
            if hook_out > 0:
                print(f"DEBUG : '{self.args.hook} {hook_args} returned {hook_out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Extract Let\'s Encrypt certificates from Traefik config.')
    parser.add_argument('-c', '--certificate', default='acme.json', type=PathType(exists=True), help='File that contains the traefik certificates (default: acme.json)')
    parser.add_argument('-d', '--directory', default='.', type=PathType(type='dir'), help='Output folder')
    parser.add_argument('-f', '--flat', action='store_true', help='Outputs all certificates into one folder')
    parser.add_argument('-r', '--restart-container', action='store_true', help="Use the docker API to restart containers that are labeled with 'traefik-certificate-extractor.restart_domain=<DOMAIN>' if the domain name of a generated certificates matches. Multiple domains can be seperated by ','")
    parser.add_argument('-l', '--restart-container-label', type=ascii, default='traefik-certificate-extractor.restart_domain', help="The Docker label to filter containers for domain names to restart (default: traefik-certificate-extractor.restart_domain)")
    parser.add_argument('-1','--one-shot', action='store_true', help="Extract certificates and exit")
    parser.add_argument('--dry-run', action='store_true', dest='dry', help="Don't write files and do not start docker containers.")
    parser.add_argument('--hook', type=PathType(exists=True), help='Hook to run before/during/after certificate export')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--include', nargs='*')
    group.add_argument('--exclude', nargs='*')
    args = parser.parse_args()

    print('DEBUG: watching path: ' + str(args.certificate))
    print('DEBUG: output path: ' + str(args.directory))

    # Create event handler and observer
    event_handler = Handler(args)

    # When running as single shot, do the work and exit.
    if args.one_shot:
        event_handler.doTheWork()
        exit(0)

    observer = Observer()

    # Register the directory to watch
    observer.schedule(event_handler, str(Path(args.certificate).parent))

    # Main loop to watch the directory
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()