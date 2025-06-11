from argparse import ArgumentParser, RawDescriptionHelpFormatter

from .driver import GenerationDriver, SUPPORTED_SYSCALLS
from .log import setup_logging

parser = ArgumentParser(formatter_class = RawDescriptionHelpFormatter,
epilog = f'''List of supported syscalls (pass to -g parameter):
    {'\n    '.join(SUPPORTED_SYSCALLS)}
''')
parser.add_argument('ftdb', help = 'path to FTDB image')
parser.add_argument('--foka', action = 'store',
                    help = 'path to FOKA json file',
                    default = '',
                    required = False)
parser.add_argument('-o', '--output', action = 'store',
                    help = 'path to output dir, defaults to ./syzdescriptor_out',
                    default = './syzdescriptor_out/',
                    required = False)
parser.add_argument('-a', '--arch', action = 'store',
                    help = 'architecture to generate syscalls for, used for \
.const files',
                    default = 'arm64',
                    required = False)
parser.add_argument('-g', '--generate', action = 'append',
                    help = 'syscall names to generate descriptions for',
                    default = SUPPORTED_SYSCALLS,
                    required = False)
parser.add_argument('-v', '--verbose', action = 'count',
                    help = 'increase verbosity',
                    default = 0,
                    required = False)
parser.add_argument('-f', '--filter-permissions', action = 'store_true',
                    help = 'filter out syscalls with root permissions',
                    default = False,
                    required = False)
parser.add_argument('--replace', action = 'store_true',
                    help = 'set replace mode for replacing placeholders with \
actual opens from FOKA',
                    default = False,
                    required = False)
parser.add_argument('--software-version', action = 'store',
                    help = 'software version of targeted device \
(used for generating info.json)',
                    default = '',
                    required = False)
parser.add_argument('--model', action = 'store',
                    help = 'targeted model (used for generating info.json)',
                    default = '',
                    required = False)
parser.add_argument('--empty-paths', action = 'store_true',
                    help = 'output empty open paths. This makes the generated \
descriptions parsable if no FOKA was passed',
                    default = False,
                    required = False)
parser.add_argument('--no-delete-empty', action = 'store_true',
                    help = "don't delete descriptions to which FOKA found \
no filesystem paths",
                    default = False,
                    required = False)

args = parser.parse_args()

def main():
    setup_logging(args.verbose)

    driver = GenerationDriver(
        args.ftdb,
        args.foka,
        args.output,
        args.arch,
        args.generate,
        args.software_version,
        args.model
    )

    if not args.replace:
        driver.generate_descriptions()

    driver.replace(args.filter_permissions, not args.no_delete_empty)
    driver.generate_info_json()

    if args.foka and args.empty_paths:
        driver.place_empty_paths()
