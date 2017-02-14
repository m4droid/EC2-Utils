#!/usr/bin/env python
from __future__ import print_function

import argparse
import getpass
import sys

import requests
from requests.auth import HTTPBasicAuth


def check_request(request):
    if not request.ok:
        print(
            'ERROR - HTTP status code {0:d} at {1:s}: {2:s}'.format(
                request.status_code,
                request.url,
                request.json()['message']
            ),
            file=sys.stderr,
        )
        exit(1)


def check_length(data, message):
    if len(data) == 0:
        print(message, file=sys.stderr)
        exit(1)


def get_github_org_keys(org_id, team_slug, username, password, pin_2fa=None, excluded_users=None):
    headers = {}

    if excluded_users is None:
        excluded_users = []

    if pin_2fa is not None:
        headers['X-GitHub-OTP'] = pin_2fa

    request = requests.get(
        'https://api.github.com/orgs/{0:s}/teams'.format(org_id),
        auth=HTTPBasicAuth(username, password),
        headers=headers,
    )
    check_request(request)

    deploy_teams = [team for team in request.json() if team['slug'] == team_slug]
    check_length(deploy_teams, 'Error: {0:s} team doesn\'t exist.'.format(team_slug))

    request = requests.get(
        'https://api.github.com/teams/{0:d}/members'.format(deploy_teams[0]['id']),
        auth=HTTPBasicAuth(username, password),
        headers=headers,
    )
    check_request(request)

    keys = []
    for user in request.json() or []:
        if user['login'] in excluded_users:
            continue

        request = requests.get(
            'https://api.github.com/users/{0:s}/keys'.format(user['login']),
            auth=HTTPBasicAuth(username, password),
            headers=headers,
        )
        check_request(request)

        keys += ['{0:s} {1:s}'.format(key['key'], user['login']) for key in request.json() or []]

    return keys


def add_keys_to_file(file_, keys):
    with open(file_, 'r') as f:
        keys_in_file = [k.strip() for k in f.read().strip().split('\n') if k.strip() != '']

        if len(keys_in_file) == 0:
            keys_in_file += keys
        else:
            # First key always wins
            keys_in_file = keys_in_file[0:1]
            if keys_in_file[0] in keys:
                keys.remove(keys_in_file[0])
            keys_in_file += keys

    with open(file_, 'w') as f:
        f.write('\n'.join(keys_in_file))


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument('--org', required=True, help='GitHub organization ID (e.g. epistemonikos)')
    parser.add_argument('--user', required=True, help='GitHub username')
    parser.add_argument('--file', required=True, help='Authorized keys file')
    parser.add_argument('--team-slug', default='deploy', help='GitHub team slug')
    parser.add_argument('--p2fa', default=False, help='Request 2FA pin')
    parser.add_argument('--token', default=None, help='User token')
    parser.add_argument('--excluded', nargs='+', help='Excluded users')

    args = parser.parse_args()

    pin_2fa = None

    if args.token is None:
        password = getpass.getpass('password: ')
        check_length(password, 'Error: password is required.')

        if args.p2fa:
            pin_2fa = getpass.getpass('2FA pin: ')
            check_length(password, 'Error: 2FA pin is required.')
    else:
        password = args.token

    keys = get_github_org_keys(
        args.org,
        args.team_slug,
        args.user,
        password,
        pin_2fa=pin_2fa,
        excluded_users=args.excluded,
    )

    add_keys_to_file(args.file, keys)


if __name__ == "__main__":
    main()
