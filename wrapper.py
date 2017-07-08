#!/usr/bin/python

import argparse
import logging
import os.path
import signal
import subprocess
import time

from cert import FakeCertManager, LetsEncryptCertManager


class Runner:

    def __init__(self, cert_manager, cert_check_interval):
        self.cert_manager = cert_manager
        self.cert_check_interval = cert_check_interval

        self.running = True

        def terminate_handler(signum, frame):
            logging.info('Received {}, terminating'.format(signal.Signals(signum).name))
            self.running = False

        signal.signal(signal.SIGINT, terminate_handler)
        signal.signal(signal.SIGTERM, terminate_handler)

        self.haproxy = None

    def run(self):
        logging.info('Starting up')
        self.cert_manager.generate()

        self._start_haproxy()

        logging.info('Starting main loop')
        while self.running:
            logging.info('Waiting for {} seconds...'.format(self.cert_check_interval))
            for _ in range(self.cert_check_interval):
                if not self.running:
                    break
                if self.haproxy.poll() is not None:
                    logging.error('haproxy has terminated with error code {}, terminating'.format(self.haproxy.returncode))
                    self.running = False
                    break
                time.sleep(1)

            number_of_renewed_certs = self.cert_manager.renew()
            if number_of_renewed_certs:
                logging.info('{} certificates were renewed, reloading haproxy'.format(number_of_renewed_certs))
                self._stop_haproxy()
                self._start_haproxy()

        self._stop_haproxy()
        logging.info('Finished.')

    def _start_haproxy(self):
        logging.info('Starting haproxy')
        self.haproxy = subprocess.Popen(["haproxy", "-f", "/usr/local/etc/haproxy/haproxy.cfg"])

    def _stop_haproxy(self):
        if self.haproxy.poll() is None:
            logging.info('Stopping haproxy gracefully')
            self.haproxy.terminate()
            try:
                self.haproxy.wait(timeout=60)
            except subprocess.TimeoutExpired:
                logging.warn('Stopping haproxy gracefully failed. Killing haproxy')
                self.haproxy.kill()


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)-15s %(levelname)-8s %(message)s')
    args = parse_args()

    cert_manager = create_cert_manager(args)

    runner = Runner(cert_manager, args.cert_check_interval)
    runner.run()


def create_cert_manager(args):
    if args.mode == 'fake':
        return FakeCertManager(args.domain, args.renew_before_expiry, args.fake_cert_lifetime)
    elif args.mode == 'stage':
        return LetsEncryptCertManager(args.domain, args.renew_before_expiry, args.email,
                                      force_renewal=args.force_renewal)
    elif args.mode == 'prod':
        raise NotImplementedError
    else:
        raise ValueError('Unknown mode {}'.format(args.mode))


def parse_args():
    parser = argparse.ArgumentParser(description='HAProxy wrapper for managing certificates')

    parser.add_argument('--mode', choices=['fake', 'stage', 'prod'], required=True,
                        help='"fake" generates a self-signed certificate. '
                             '"stage" uses the letsencrypt staging server. '
                             '"prod" uses the regular letsencrypt server. '
                             'Use this only after verifying your setup in stage mode.')
    parser.add_argument('--cert-check-interval', metavar='INTERVAL', default=24 * 3600, type=int,
                        help='Perform certificate check every INTERVAL seconds.')
    parser.add_argument('--renew-before-expiry', metavar='INTERVAL', default=2 * 24 * 3600, type=int,
                        help='Renew certificate INTERVAL seconds before expiry')
    parser.add_argument('--fake-cert-lifetime', metavar='DAYS', default=90, type=int,
                        help='Lifetime for fake certificates. Ignored for stage/prod mode.')
    parser.add_argument('--email', help='Email address to register for letsencrypt. Ignored for fake mode.')
    parser.add_argument('--force-renewal', action='store_true',
                        help='Force renewal for letsencrypt. Ignored for fake mode.')
    parser.add_argument('domain', nargs='+')

    args = parser.parse_args()
    if args.mode in {'stage', 'prod'} and not args.email:
        parser.error('--email is required for mode {}'.format(args.mode))
    return args


main()
