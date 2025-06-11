import io, libftdb

from typing import Optional, Union

from .passes import Fops, PointerCycle, MemberBounds

class BaseDeclaration:
    def __str__(self) -> str:
        return str('')

class RecordDeclaration(BaseDeclaration):
    name: str

    def __init__(self, name: str):
        self.name = name

    def __str__(self) -> str:
        return f'{self.name}'

class EnumDeclaration(BaseDeclaration):
    def __init__(self, layout_type, inside_type):
        self.layout_type = layout_type
        self.inside_type = inside_type

    def __str__(self) -> str:
        return f'flags[{self.layout_type}, {self.inside_type}]'

class IntegerDeclaration(BaseDeclaration):
    size: int

    def __init__(self, size: int):
        self.size = size

    def __str__(self) -> str:
        return f'int{self.size}'

class VoidDeclaration(BaseDeclaration):
    def __init__(self):
        pass

    def __str__(self) -> str:
        return 'void'

class ArrayDeclaration(BaseDeclaration):
    inside_type: BaseDeclaration
    size: int

    def __init__(self, inside_type, size: int):
        self.inside_type = inside_type

        # Syzkaller does not support zero sized arrays, it it possible to
        # express flexible array memebrs?
        self.size = size if size > 0 else 1

    def __str__(self) -> str:
        return f'array[{self.inside_type}, {self.size}]'

class PointerDeclaration(BaseDeclaration):
    optional: bool
    inside_type: BaseDeclaration

    def __init__(self, inside_type: BaseDeclaration):
        self.inside_type = inside_type
        self.optional = False

    def __str__(self) -> str:
        if isinstance(self.inside_type, VoidDeclaration):
            return f'buffer[inout]'
        elif self.optional:
            return f'ptr[inout, {self.inside_type}, opt]'
        else:
            return f'ptr[inout, {self.inside_type}]'

class LengthDeclaration(BaseDeclaration):
    field_name: str
    inside_type: BaseDeclaration

    def __init__(self, field_name: str, inside_type: BaseDeclaration):
        self.field_name = field_name
        self.inside_type = inside_type

    def __str__(self) -> str:
        return f'len[{self.field_name}, {self.inside_type}]'

class RecordDefinition(BaseDeclaration):
    name: str
    fields: list
    union: bool

    def __init__(self, name: str, fields: list, union: bool = False):
        self.name = name
        self.fields = fields
        self.union = union

    def __str__(self) -> str:
        buffer = io.StringIO()

        buffer.write(f'{self.name} ')
        if self.union:
            buffer.write('[')
        else:
            buffer.write('{')
        buffer.write('\n')

        for field in self.fields:
            buffer.write(f'\t{field}\n')

        if self.union:
            buffer.write(']')
        else:
            buffer.write('}')

        buffer.write('\n\n')

        return buffer.getvalue()

class EnumDefinition(BaseDeclaration):
    name: str
    values: list

    def __init__(self, name: str, values: list):
        self.name = name
        self.values = values

    def __str__(self) -> str:
        buffer = io.StringIO()

        buffer.write(f'{self.name} = ')

        for i in range(len(self.values)):
            buffer.write(f'{self.values[i]}')
            if i != len(self.values) - 1:
                buffer.write(', ')

        buffer.write('\n\n')

        return buffer.getvalue()

class RecordField:
    name: str
    type_decl: BaseDeclaration

    def __init__(self, name: str, type_decl: BaseDeclaration):
        self.name = name
        self.type_decl = type_decl

    def __str__(self) -> str:
        return f'{self.name} {self.type_decl}'

class IoctlDeclaration(BaseDeclaration):
    fd_name: str
    label: str
    argument: BaseDeclaration

    def __init__(self, fd_name: str, label: str, argument: BaseDeclaration):
        self.fd_name = fd_name
        self.label = label
        self.argument = argument

    def __str__(self) -> str:
        return f'''ioctl${self.label}_syzdescriptor(fd {self.fd_name}, \
cmd const[{self.label}_syzdescriptor], arg {self.argument})\n\n'''

class OpenDeclaration:
    label: str
    open_path: str
    fd_name: str

    def __init__(self, label: str, open_path: str, fd_name: str):
        self.label = label
        self.open_path = open_path
        self.fd_name = fd_name

    def __str__(self) -> str:
        return f'''openat${self.label}_syzdescriptor(fd const[AT_FDCWD], file \
ptr[in, string[{self.open_path}_syzdescriptor]], flags flags[open_flags], \
mode const[0]) {self.fd_name}\n\n'''

class ConstantDefinition:
    name: str

    def __init__(self, name, value):
        self.name = name
        self.value = value

    def __str__(self):
        return f'{self.name}_syzdescriptor = {self.value}\n'

class FlagsDefinition:
    def __init__(self, values):
        self.values = values

    def __str__(self):
        buffer = io.StringIO()

        for i in range(len(self.values)):
            if isinstance(self.values[i], str):
                buffer.write(f'"{self.values[i].__str__()}"')
            else:
                buffer.write(self.values[i].__str__())
            if i != len(self.values) - 1:
                buffer.write(', ')

        return buffer.getvalue()

class Generator:
    ftdb: libftdb.ftdb
    bounds: Optional[dict[int, list[MemberBounds]]]
    cycles: Optional[dict[int, list[PointerCycle]]]
    generated_consts: dict[str, Union[str, int]]
    generated_types: dict[int, list[str]]

    def __init__(self, ftdb):
        self.ftdb = ftdb
        self.generated_consts = dict()
        self.generated_types = dict()

    def __find_new_const_name(self, name):
        while name in self.generated_consts.keys():
            name += '_'
        return name

    def __detypedef(self, type_id):
        db_type = self.ftdb['types'].entry_by_id(type_id)

        while db_type['class'] == 'typedef':
            db_type = self.ftdb['types'].entry_by_id(db_type['refs'][0])

        return db_type['id']

    def __rename_already_used_consts(self, commands):
        to_remove = set()

        for label, value, type_id in commands:
            if label in self.generated_consts.keys():
                to_remove.add((label, value, type_id))

        for el in to_remove:
            new_name = self.__find_new_const_name(el[0])
            commands.remove(el)
            commands.add((new_name, el[1], el[2]))

    def generate_const_file(self, fop: Fops) -> str:
        buffer = io.StringIO()

        self.__rename_already_used_consts(fop.commands)

        for label, value, _ in fop.commands:
            buffer.write(ConstantDefinition(label, value).__str__())
            self.generated_consts[label] = value

        return buffer.getvalue()

    def __assign_name_to_type(self, typeid: int) -> Optional[tuple[int, str]]:
        if self.generated_types.get(typeid):
            new_name = self.generated_types[typeid][-1] + '_'
            self.generated_types[typeid].append(new_name)

            return (typeid, new_name)
        else:
            db_type = self.ftdb['types'].entry_by_id(self.__detypedef(typeid))
            if db_type['class'] not in ['record', 'enum']:
                return None
            name = db_type['str']
            if not name: # Anonymous records
                name = f"ANONTYPE_{typeid}"
            self.generated_types[typeid] = [name]

            return (typeid, name)

    def __generate_type_declaration(self, type_id: int) -> BaseDeclaration:
        db_type = self.ftdb['types'].entry_by_id(self.__detypedef(type_id))

        if db_type['class'] == 'record':
            if not self.generated_types.get(db_type['id']):
                return BaseDeclaration()
            return RecordDeclaration(self.generated_types[db_type['id']][-1])
        elif db_type['class'] == 'const_array' or db_type['class'] == 'incomplete_array':
            size = db_type['size']
            if size == 0:
                size = 1
            underlying_type = self.ftdb['types'].entry_by_id(db_type['refs'][0])
            return ArrayDeclaration( \
                self.__generate_type_declaration(db_type['refs'][0]),
                int(size / underlying_type['size']))
        elif db_type['class'] == 'enum':
            if not self.generated_types.get(db_type['id']):
                return BaseDeclaration()
            return EnumDeclaration(self.generated_types[db_type['id']][-1],
                                   IntegerDeclaration(32))
        elif db_type['class'] == 'pointer':
            return PointerDeclaration( \
                self.__generate_type_declaration(self.__detypedef(db_type['refs'][0])))
        elif db_type['class'] == 'builtin' and db_type['str'] == 'void':
            return VoidDeclaration()
        elif db_type['class'] == 'builtin' and db_type['size'] > 64:
            assert not (db_type['size'] % 8)
            return ArrayDeclaration(IntegerDeclaration(8), int(db_type['size'] / 8))
        elif db_type['class'] == 'builtin':
            return IntegerDeclaration(db_type['size'])

        return BaseDeclaration()

    def generate_record_definition(self, type_id: int, name: str, union: bool = False) -> RecordDefinition:
        anonymous_count = 0

        def filter_anonymous_type_names(type_name):
            if type_name == '__!anonrecord__' or type_name == '__!recorddecl__':
                nonlocal anonymous_count
                type_name = f'anonymous{anonymous_count}'
                anonymous_count += 1
            return type_name

        db_type = self.ftdb['types'].entry_by_id(self.__detypedef(type_id))
        fields = [
            RecordField(filter_anonymous_type_names(name),
                        self.__generate_type_declaration(type_id))

            for name, type_id in list(zip(db_type['refnames'], db_type['refs']))
        ]

        if self.bounds.get(type_id):
            for bound in self.bounds[type_id]:
                type_decl = fields[bound.binding_member].type_decl.__str__()
                fields[bound.binding_member].type_decl = LengthDeclaration(
                    fields[bound.bound_member].name,
                    type_decl
                )

        if self.cycles.get(type_id):
            for cycle in self.cycles[type_id]:
                fields[cycle.member_position].type_decl.optional = True

        return RecordDefinition(name, fields, union)

    def generate_enum_definition(self, type_id: int, name: str) -> EnumDefinition:
        return EnumDefinition(name,
                              self.ftdb['types'] \
                                .entry_by_id(self.__detypedef(type_id))['values'])

    def __generate_type_definition(self, type_id: int, name: str) -> BaseDeclaration:
        db_type = self.ftdb['types'].entry_by_id(self.__detypedef(type_id))

        # We only need to define these, more complex types
        if db_type['class'] == 'record' and not db_type['union']:
            return self.generate_record_definition(type_id, name)
        elif db_type['class'] == 'record' and db_type['union']:
            return self.generate_record_definition(type_id, name, True)
        elif db_type['class'] == 'enum':
            return self.generate_enum_definition(type_id, name)

        return BaseDeclaration()

    def __generate_ioctl_declaration(self, fd_name: str, label: str, type_id: int) -> BaseDeclaration:
        db_type = self.ftdb['types'].entry_by_id(self.__detypedef(type_id))
        argument_type = self.__generate_type_declaration(type_id)

        if type(argument_type) is BaseDeclaration: # This can be prettier
            return BaseDeclaration()

        if db_type['class'] == 'pointer':
            return IoctlDeclaration(fd_name, label, argument_type)
        return IoctlDeclaration(fd_name, label, PointerDeclaration(argument_type))

    def __generate_open_declaration(self, label: str, open_path: str, fd_name: str) -> OpenDeclaration:
        return OpenDeclaration(label, open_path, fd_name)

    def __generate_header(self, fd_name, path_constant, anchor_id):
        """Create a header for interface description

        :param intf: interface name (fops variable name), used for initializing
        an fd
        :returns: header for desciption files in syzlang
        """
        import datetime
        return f"""# Generated by syzdescriptor on {datetime.date.today()}
# Path constant is: {path_constant}
# Anchor function ID is: {anchor_id}
include <linux/ioctl.h>
include <linux/types.h>

resource {fd_name}[fd]\n
"""

    def generate_description(self, fop: Fops) -> str:
        buffer = io.StringIO()
        deps = set(filter(lambda x: x is not None,
                           [self.__assign_name_to_type(x) for x in fop.deps]))

        fd_name = 'fd_' + fop.name
        path = self.__find_new_const_name(f'SYZDESCRIPTOR_PATH_{fop.syscall_id}')
        self.generated_consts[path] = ''
        buffer.write(self.__generate_header(fd_name, path, fop.syscall_id))

        buffer.write(self.__generate_open_declaration(fop.name,
                                                      path,
                                                      fd_name).__str__())

        for label, _, type_id in fop.commands:
            buffer.write(self.__generate_ioctl_declaration(fd_name,
                                                           label,
                                                           type_id).__str__())

        buffer.write('\n')

        self.bounds = fop.pointer_bounds
        self.cycles = fop.pointer_cycles

        for id, name in deps:
            buffer.write(self.__generate_type_definition(id, name).__str__())

        self.bounds = None
        self.cycles = None

        return buffer.getvalue()
