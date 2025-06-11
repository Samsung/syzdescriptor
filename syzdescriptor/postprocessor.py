import os, json, logging

from .syzlang import ConstantDefinition, FlagsDefinition

class Postprocessor:
    OPEN_PLACEHOLDER = '# Anchor function ID is: '
    PATH_PLACEHOLDER = '# Path constant is: '

    OPEN_PREFIX = 'openat$'
    IOCTL_PREFIX = 'ioctl$'

    def __init__(
        self,
        ftdb,
        foka_path,
        working_directory,
        architecture
    ):
        self.ftdb = ftdb
        self.foka_path = foka_path
        self.working_directory = working_directory
        self.architecture = architecture
        self.foka = {}
        self.reverse_foka = {}
        self.file_cache = set()
        self.__update_file_cache()

    def is_path_dangerous(self, path):
        if self.foka[path] == 'root' \
            or path.startswith('/dev/block') \
            or path.startswith('/dev/usb-ffs/adb'):
                return True
        return False

    @classmethod
    def strip_function_names(cls, name):
        """Takes string and strips it from unnecessary tokens added by FOKA

        :param name: (string) function name string from FOKA
        :returns: (string) stripped name
        """
        if ' [' in name:
            name = name[0:name.find(' [')]
        if name.endswith('.cfi_jt'):
            name = name[0:-len('.cfi_jt')]
        return name

    @classmethod
    def get_colon_separated_value(cls, buffer, lhs):
        off = buffer.find(lhs)
        if off == -1:
            return ''

        eol = buffer[off + len(lhs):].find('\n')
        return buffer[off + len(lhs):off + len(lhs) + eol]

    def __create_reverse_foka(self):
        for k, v in self.foka.items():
            ioctl = v['ioctl'][-1]
            if ioctl != '0x0':
                ioctl = self.strip_function_names(ioctl)
                if not self.reverse_foka.get(ioctl):
                    self.reverse_foka[ioctl] = [k]
                else:
                    self.reverse_foka[ioctl].append(k)

    def __load_foka(self):
        self.foka = json.loads(open(self.foka_path, 'r').read())
        self.__create_reverse_foka()

    def __update_file_cache(self):
        self.file_cache = set(
            [os.path.join(dir, file)
             for (dir, _, files) in os.walk(self.working_directory)
             for file in files
             if file.endswith('.txt')]
        )

    def get_function_name_by_id(self, fid):
        return self.ftdb['funcs'].entry_by_id(fid)['name']

    def __extract_fops_name_from_path(self, path):
        return path[:path.find('.txt')].split('/')[-1]

    def __extract_function_name_from_description(self, buffer):
        fid = int(self.get_colon_separated_value(buffer, self.OPEN_PLACEHOLDER))
        return self.get_function_name_by_id(fid)

    def __remove_descriptions(self, name):
        os.remove(os.path.join(self.working_directory, f'{name}.txt'))
        os.remove(os.path.join(self.working_directory, f'{name}_{self.architecture}.const'))

    def replace(
            self,
            filter_permissions,
            delete_empty,
            path_limit = 10
        ):
        self.__load_foka()
        self.__update_file_cache()

        for path in self.file_cache:
            self.__replace(path, filter_permissions, delete_empty, path_limit)

    def is_function_dangerous(self, f, filter_permissions, path_limit = 10):
        paths = self.reverse_foka.get(f)
        dangerous = False
        for i in range(0 if not paths else len(paths)):
            if (dangerous := (filter_permissions
                                and self.is_path_dangerous(paths[i]))) \
                or i >= path_limit:
                break

        return dangerous

    def __replace(self, path, filter_permissions, delete_empty, path_limit = 10):
        fops = self.__extract_fops_name_from_path(path)
        contents = open(path, 'r').read()
        function_name = self.__extract_function_name_from_description(contents)
        if self.is_function_dangerous(function_name, filter_permissions, path_limit):
            logging.info('f{fops} is dangerous, deleting')
            self.__remove_descriptions(fops)
            return
        const = self.get_colon_separated_value(contents, self.PATH_PLACEHOLDER)
        paths = self.reverse_foka.get(function_name)

        if not paths and not delete_empty:
            logging.debug(f'Omitting {path} deletion due to --no-delete-empty')
            return
        elif not paths:
            logging.info(f'{fops} has no FOKA paths, deleting')
            self.__remove_descriptions(fops)
            return

        self.rewrite_file(
            path,
            const,
            [paths[i] for i in range(min(len(paths), path_limit))]
        )

    def place_empty_paths(self):
        self.__update_file_cache()

        for path in self.file_cache:
            self.__place_empty_paths(path)

    def __place_empty_paths(self, path):
        contents = open(path, 'r').read()
        const = self.get_colon_separated_value(contents, self.PATH_PLACEHOLDER)
        self.rewrite_file(path, const, "/dev/null")

    def rewrite_file(self, path, constant, paths):
        if isinstance(paths, list):
            paths = FlagsDefinition(paths)

        with open(path, 'a') as f:
            logging.debug(f'Appending to {path}')
            f.write(
                ConstantDefinition(
                    constant,
                    paths
                ).__str__()
            )

    def __find_syscall_name(self, buffer, pattern):
        ret = []
        while (off := buffer.find(pattern)) != -1:
            end_rel = buffer[off:].find('(')
            end_off = off + end_rel
            ret.append(buffer[off:end_off])
            buffer = buffer[end_off:]
        return ret

    def generate_info_json(self, model, software_version):
        self.__update_file_cache()

        info_path = os.path.join(self.working_directory, 'info.json')
        if os.path.exists(info_path):
            os.remove(info_path)

        syscalls = []
        for path in self.file_cache:
            with open(path, 'r') as f:
                contents = f.read()
                syscalls += self.__find_syscall_name(contents, self.OPEN_PREFIX)
                syscalls += self.__find_syscall_name(contents, self.IOCTL_PREFIX)

        open(info_path, 'w') \
            .write(
                json.dumps(
                    {
                        'model': model,
                        'version': software_version,
                        'enabled_syscalls': syscalls
                    }
                )
            )
