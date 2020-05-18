#!/usr/bin/env python3
import os
import re
import sys
import argparse
import subprocess


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
VERSION_FILE_PATH = os.path.join(PROJECT_ROOT, 'version', 'version.go')

RELEASE_NOTE_TEMPLATE = """
## Changes in this release

{commits}

## Ecosystem

| Component  | Baseline |
| ---------- | -------- |
| Tendermint | 0.32.11  |

## Pull Requests

{pull_requests}

"""


def _markdown_list(items):
    if len(items) == 0:
        return '* None'
    
    return '\n'.join(
        map(
            lambda x: '* {}'.format(x),
            items
        )
    )


def _version(text):
    match = re.match(r'\d+\.\d+\.\d+', text)
    if match is None:
        print('Unrecognised version: {}. Expected in form "1.2.3"'.format(text))
        sys.exit(1)
    return text


def parse_commandline():
    parser = argparse.ArgumentParser()
    parser.add_argument('version', type=_version, help='The next version number')
    # parser.add_argument('previous_version', type=_version, help='The previous version number')
    return parser.parse_args()


def update_version_file(version):
    with open(VERSION_FILE_PATH, 'r') as input_file:
        contents = input_file.read()

    contents = re.sub(r'(TMCoreSemVer\s+=\s+).+?"', r'\1"{}"'.format(version), contents)

    with open(VERSION_FILE_PATH, 'w') as output_file:
        output_file.write(contents)


    # add and commit the changes if that is necessary
    cmd = [
        'git',
        'diff',
        '--exit-code',
        os.path.relpath(VERSION_FILE_PATH, PROJECT_ROOT),
    ]
    with open(os.devnull, 'w') as null_file:
        exit_code = subprocess.call(cmd, cwd=PROJECT_ROOT, stdout=null_file, stderr=subprocess.STDOUT)

    if exit_code != 0:
        cmd = [
            'git',
            'add',
            os.path.relpath(VERSION_FILE_PATH, PROJECT_ROOT),
        ]
        subprocess.check_call(cmd, cwd=PROJECT_ROOT)

        cmd = [
            'git',
            'commit',
            '-m', 'Update version to v{}'.format(version),
        ]
        subprocess.check_call(cmd, cwd=PROJECT_ROOT)


def create_commit_list(previous_version):
    cmd = [
        'git',
        'log',
        '--format=%s',
        '{}..HEAD'.format(previous_version),
    ]

    return subprocess.check_output(cmd).decode().splitlines()


def create_pr_list(commit_list):
    return list(
        filter(
            lambda x: re.search(r'\(#\d+\)$', x) is not None,
            commit_list
        )
    )


def determine_previous_tag():
    cmd = ['git', 'describe', '--abbrev=0', '--tags']
    return subprocess.check_output(cmd).decode().strip()


def switch_to_release_candidate_branch(version):
    branch_name = 'release-candidate/v{}'.format(version)

    # work out what the current branch is
    cmd = ['git', 'rev-parse', '--abbrev-ref', 'HEAD']
    current_branch = subprocess.check_output(cmd, cwd=PROJECT_ROOT).decode().strip()

    if current_branch != branch_name:
        cmd = ['git', 'checkout', '-b', branch_name]
        subprocess.check_call(cmd, cwd=PROJECT_ROOT)


def main():
    args = parse_commandline()

    # create the release candidate branch
    switch_to_release_candidate_branch(args.version)

    # update the version file (and commit if necessary)
    update_version_file(args.version)

    # work out what the previous tag was
    previous_release = determine_previous_tag()

    print('Previous release: {}'.format(previous_release))

    # build up a list of changes for the current version
    commit_list = create_commit_list(previous_release)
    pr_list = create_pr_list(commit_list)

    # create the tag
    cmd = [
        'git', 'tag', '-a',
        'v{}'.format(args.version),
        '-m', 'Tag: v{}'.format(args.version),
    ]
    # subprocess.check_call(cmd)

    release_note_draft = RELEASE_NOTE_TEMPLATE.format(
        commits=_markdown_list(commit_list),
        pull_requests=_markdown_list(pr_list),
    )

    print('DRAFT RELEASE NOTES')
    print()
    print('---')
    print(release_note_draft)


if __name__ == '__main__':
    main()