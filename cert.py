from datetime import datetime
import logging
import os.path
import subprocess
import time
import ssl


class CertManager:

    TARGET_CERT_FOLDER = '/var/cert'

    def __init__(self, domains, renew_seconds_before_expiry):
        self.domains = domains
        self.renew_seconds_before_expiry = renew_seconds_before_expiry

    def generate(self):
        logging.info('Generating certificates if required (offline mode)')
        for domain in self.domains:
            if self.should_certificate_be_renewed(domain):
                self.generate_certificate(domain)

    def renew(self):
        logging.info('Renewing certificates if required (online mode)')
        changed = 0
        for domain in self.domains:
            if self.should_certificate_be_renewed(domain):
                self.renew_certificate(domain)
                changed += 1
        return changed

    def target_cert(self, domain):
        return os.path.join(self.TARGET_CERT_FOLDER, domain + '.pem')

    def merge_key_and_certificate(self, domain):
        logging.info('Merging key and certificate for domain {}'.format(domain))
        create_dir(os.path.join(self.TARGET_CERT_FOLDER, domain))
        with open(self.target_cert(domain), 'w') as out:
            for item in ['privkey.pem', 'cert.pem']:
                with open(os.path.join(self.SRC_CERT_ROOT, domain, item), 'r') as cert:
                    out.write(cert.read())


    def should_certificate_be_renewed(self, domain):
        logging.info('Checking validity of certificate for {}'.format(domain))
        if not os.path.isfile(self.target_cert(domain)):
            logging.info('No certificate found for {}'.format(domain))
            return True
        result = subprocess.check_output(['openssl', 'x509', '-enddate', '-noout', '-in',
                                          self.target_cert(domain)])
        _, cert_time = result.decode().strip().split('=')
        try:
            expires_at = ssl.cert_time_to_seconds(cert_time)
        except ValueError:
            logging.error('Could not convert certificate validity time from output {}'.format(result))
            return True
        renew_at = expires_at - self.renew_seconds_before_expiry
        renew = time.time() >= renew_at
        logging.info('Certificate will expire at {} (renewal scheduled for {}): {}renewing'
                     .format(datetime.fromtimestamp(expires_at),
                             datetime.fromtimestamp(renew_at),
                             '' if renew else 'not '))
        return renew


class FakeCertManager(CertManager):

    SRC_CERT_ROOT = '/var/fake_cert'

    def __init__(self, domains, renew_seconds_before_expiry, cert_lifetime_days):
        super().__init__(domains, renew_seconds_before_expiry)
        self.cert_lifetime_days = cert_lifetime_days

    def generate_certificate(self, domain):
        self.generate_fake_certificate(domain)
        self.merge_key_and_certificate(domain)

    def renew_certificate(self, domain):
        self.generate_certificate(domain)

    def generate_fake_certificate(self, domain):
        logging.info('Generating fake certificate for domain {}'.format(domain))
        dst_dir = os.path.join(self.SRC_CERT_ROOT, domain)
        create_dir(dst_dir)

        subprocess.call([
            'openssl', 'req', '-new', '-nodes', '-x509',
            '-subj', '/CN={}'.format(domain),
            '-days', '{}'.format(self.cert_lifetime_days),
            '-keyout', os.path.join(dst_dir, 'privkey.pem'),
            '-out', os.path.join(dst_dir, 'cert.pem'),
            '-extensions', 'v3_ca',
        ])


def create_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)
