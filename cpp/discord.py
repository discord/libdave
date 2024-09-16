#!/usr/bin/env python3

from __future__ import print_function

import hashlib
import os
import subprocess
import sys
import tempfile

# ruff: noqa: E402

script_path = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))  # noqa: E402
if __name__ == '__main__' and __package__ is None:  # noqa: E402  # pyright: ignore [reportUnnecessaryComparison]
    sys.path.append(os.path.join(PROJECT_ROOT, 'tools', 'native'))  # noqa: E402
    sys.path.append(os.path.join(PROJECT_ROOT, 'tools', 'python_scripts'))  # noqa: E402

import bootstrap as tools_bootstrap

tools_bootstrap.bootstrap()  # noqa: E402
import click
import host

import tools

DEFAULT_CORPUS_PATH = os.path.join(script_path, 'afl_driver', 'input')
DEFAULT_OUTPUT_PATH = os.path.join(script_path, 'build', 'afl', 'output')
DEFAULT_DRIVER_PATH = os.path.join(script_path, 'build', 'afl', 'afl_driver')


@click.group(context_settings=dict(help_option_names=['-h', '--help']))
def cli():
    pass


@cli.command('build-afl-driver')
@click.option('-d', '--debug', help='make debug build', is_flag=True)
@click.option('--asan/--no-asan', help='control wheter or not to build with address sanitizer', default=False)
def build_afl_driver(debug, asan):
    root_target = '//discord_common/native/dave'
    cxx_standard = 'c++20' if host.is_linux() else 'c++17'

    if asan and not debug:
        debug = True
        print('Address sanitizer requires debug build, enabling debug build')

    args = [
        'product=""',
        'root_target="{}"'.format(root_target),
        'target_cpu="{}"'.format(host.DEFAULT_ARCH),
        'cxx_standard="{}"'.format(cxx_standard),
        'is_debug={}'.format('true' if debug else 'false'),
        'use_afl_toolchain=true',
        'is_asan={}'.format('true' if asan else 'false'),
        'use_libfuzzer=true',
    ]

    build_path = os.path.join(script_path, 'build', 'afl')
    subprocess.check_call([tools.gn(), 'gen', '--args={}'.format(' '.join(args)), build_path])
    subprocess.check_call([tools.ninja(), '-C', os.path.relpath(build_path, os.getcwd()), 'afl_driver'])


@cli.command('fuzz-afl-driver')
def fuzz_afl_driver():
    fuzz_args = [
        '-i',
        os.path.relpath(DEFAULT_CORPUS_PATH),
        '-o',
        os.path.relpath(DEFAULT_OUTPUT_PATH),
        '--',
        os.path.relpath(DEFAULT_DRIVER_PATH),
    ]

    env = os.environ.copy()
    env['AFL_AUTORESUME'] = '1'
    subprocess.check_call(['afl-fuzz'] + fuzz_args, env=env)


@cli.command('minimize-corpus')
@click.option('-i', '--input-path', help='path to the input corpus', required=False, default=DEFAULT_CORPUS_PATH)
@click.option('-o', '--output-path', help='path to the output corpus', required=False, default=DEFAULT_CORPUS_PATH)
@click.option('-d', '--driver-path', help='path to the driver binary', required=False, default=DEFAULT_DRIVER_PATH)
def minimize_corpus(input_path, output_path, driver_path):
    with tempfile.TemporaryDirectory() as temp_dir:
        unique_dir = os.path.join(temp_dir, 'unique')
        min_dir = os.path.join(temp_dir, 'min')

        env = os.environ.copy()
        env['AFL_MAP_SIZE'] = '4194304'

        cmin_binary = 'afl-cmin' if host.is_linux() else 'afl-cmin.bash'
        subprocess.check_call([cmin_binary, '-i', input_path, '-o', unique_dir, '--', driver_path, '@@'], env=env)

        os.makedirs(min_dir, exist_ok=True)

        for root, _, files in os.walk(unique_dir):
            for file in files:
                input_file = os.path.join(root, file)
                output_file = os.path.join(min_dir, file)

                if not file.startswith('test-input'):
                    file_id = None
                    with open(input_file, 'rb') as f:
                        file_id = hashlib.sha256(f.read()).hexdigest()[:12]
                    output_file = os.path.join(min_dir, f'test-input-{file_id}.bin')

                subprocess.check_call(['afl-tmin', '-i', input_file, '-o', output_file, '--', driver_path], env=env)

        # Empty the output directory
        for root, _, files in os.walk(output_path):
            for file in files:
                os.remove(os.path.join(root, file))

        # Move the minimized files to the output directory
        for root, _, files in os.walk(min_dir):
            for file in files:
                os.rename(os.path.join(root, file), os.path.join(output_path, file))


if __name__ == '__main__':
    cli()
