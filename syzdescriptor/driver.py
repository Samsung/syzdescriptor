import logging, sys, os, shutil

from libftdb import ftdb

from .passes import IoctlAnalysisPass, TypeAnalysisPass, FopsCollector, \
    PointerCyclesPass, PointerBoundsPass, BasePass
from .syzlang import Generator
from .postprocessor import Postprocessor

"""This array specifies what specific fields in what specific types are supported
by syzdescriptor currently.

The format is pretty simple, and it can be passed by the user on the command-line
if syzdescriptor supports it.
"""
SUPPORTED_SYSCALLS = [
        'file_operations:unlocked_ioctl',
        'proc_ops:proc_ioctl',
        'uart_ops:ioctl'
]

class GenerationDriver:
    """Driver for syzdescriptor operations.

    Most functions that do not start with double-dash should roughly correspond
    to syzdescriptor command line options.
    """
    def __init__(
            self,
            db_path,
            foka_path,
            output_path,
            architecture,
            target_syscalls = SUPPORTED_SYSCALLS,
            software_version = '',
            model = ''
        ):
        self.db_path = db_path

        try:
            self.ftdb = ftdb(db_path, quiet = True)
        except Exception as e:
            logging.error(e)
            sys.exit(1)

        self.collector = FopsCollector(self.ftdb)
        self.generator = Generator(self.ftdb)

        self.passes = [
            (IoctlAnalysisPass(self.ftdb), True),
            (TypeAnalysisPass(self.ftdb), True),
            (PointerCyclesPass(self.ftdb), False),
            (PointerBoundsPass(self.ftdb), False)
        ]

        self.target_syscalls = target_syscalls
        self.output_path = output_path
        self.architecture = architecture
        self.software_version = software_version
        self.model = model
        self.foka_path = foka_path

        self.postprocessor = Postprocessor(
            self.ftdb,
            foka_path,
            self.output_path,
            self.architecture
        )

    def __validate_targeted_syscalls(self):
        for syscall in self.target_syscalls:
            if syscall not in SUPPORTED_SYSCALLS:
                logging.error(f'unsupported syscall: {syscall}')
                sys.exit(1)

    def __create_output_directory(self):
        logging.info(f'Creating working directory: {self.output_path}')
        if not os.path.exists(self.output_path):
            os.mkdir(self.output_path)
        else:
            shutil.rmtree(self.output_path, ignore_errors = True)
            if not os.path.exists(self.output_path):
                os.mkdir(self.output_path)

    def generate_descriptions(self):
        self.__validate_targeted_syscalls()
        self.__create_output_directory()
        self.__generate_descriptions()

    def __generate_descriptions(self):
        logging.info(f'Generating descriptions')
        fops = [fop
            for syscall in self.target_syscalls
            for fop in self.collector.collect_fops(syscall.split(':')[0],
                                                   syscall.split(':')[1])]
        for fop in fops:
            self.__generate_description(fop)

    def __generate_description(self, fop):
        logging.debug(f'Generating description for {fop.syscall_id} {fop.name}')
        for p, skip_on_fail in self.passes:
            assert isinstance(p, BasePass), 'Element in passes array is not \
                derived from BasePass class'

            success = False
            try:
                success = p.process(fop)
            except Exception as e:
                logging.error('Exception occurred during {} pass: {}'
                              .format(type(p).__name__, e))
                sys.exit(1)

            if skip_on_fail and not success:
                logging.warning('Discarding fop {} due to fail in pass {}'
                                .format(fop.name, type(p).__name__))
                return
            elif not success:
                logging.warning('Skipping pass {} in fop {} due to processing failure'
                                .format(type(p).__name__, fop.name))

        self.dump_file(fop)

    def dump_file(self, fop):
        const_path = os.path.join(self.output_path, f'{fop.name}_{self.architecture}.const')
        desc_path = os.path.join(self.output_path, f'{fop.name}.txt')
        with open(const_path, 'x') as f:
            f.write(self.generator.generate_const_file(fop))

        with open(desc_path, 'x') as f:
            f.write(self.generator.generate_description(fop))

        logging.info(f'Generated descriptions for fop {fop.name} in {desc_path}')

    def place_empty_paths(self):
        self.postprocessor.place_empty_paths()

    def replace(self, filter_permissions, delete_empty):
        if not self.foka_path:
            return
        self.postprocessor.replace(filter_permissions, delete_empty)

    def generate_info_json(self):
        if not self.model and not self.software_version:
            return
        self.postprocessor.generate_info_json(self.model, self.software_version)
