import re, abc, libftdb
from typing import Optional

class PointerCycle:
    """Named tuple/record for storing pointer cycle information
    """
    def __init__(self, cycled_id: int, member_position: int):
        self.cycled_id = cycled_id
        self.member_position = member_position

class MemberBounds:
    """Named tuple/record for storing member bounds information
    """
    def __init__(self, type_id: int, binding_member: int, bound_member: int):
        self.type_id = type_id
        self.binding_member = binding_member
        self.bound_member = bound_member

    def __repr__(self):
        return f"""{{ 'binding_member': {self.binding_member}, \
'bound_member': {self.bound_member} }}"""

    def __hash__(self):
        return hash((self.type_id, self.binding_member, self.bound_member))

    def __eq__(self, other):
        if self.type_id == other.type_id and \
           self.binding_member == other.binding_member and \
           self.bound_member == other.bound_member:
           return True

        return False

class Fops:
    """Record type which is passed between analyzers, aggregating data from them.

    It's basis of high-level syzdescriptor operations.
    """
    name: str
    syscall_id: int
    commands: set[tuple[str, int, int]]
    deps: set[int]
    pointer_cycles: dict[int, list[PointerCycle]]
    pointer_bounds: dict[int, list[MemberBounds]]

    def __init__(self, name: str, syscall_id: int):
        """Construct Fops

        :param name: name of fop instance which contains this syscall_id
        :param syscall_id: FTDB Function ID of the collected syscall
        """
        self.name = name
        self.syscall_id = syscall_id

class FopsCollector:
    """FopsCollector does really what it names says it does.

    Previously, it was a part of FopsPass (now BasePass), but I figured
    that not many other passes use this data so it got separated.

    In the case of syzdescriptor, because of how I wanted to make it somewhat modular,
    the OOP'ness is pretty neat. Let's hope it does not go bad in the future.
    """
    FILE_OPERATIONS = [
        'file_operations',
        'proc_ops',
        'uart_ops'
    ]

    ftdb: libftdb.ftdb
    types: dict[str, list]
    fields: dict[int, list[str]]
    vars: list

    def __init__(self, ftdb: libftdb.ftdb):
        """Construct FopsCollector

        :param ftdb: An initialized libftdb.ftdb instance
        """
        self.ftdb = ftdb
        self.types = dict()
        self.fields = dict()
        for typ in self.get_fops_types():
            if v := self.types.get(typ['str']):
                v.append(typ)
            else:
                self.types[typ['str']] = [typ]


        for _, types in self.types.items():
            for typ in types:
                self.fields[typ['id']] = typ['refnames']

        # We'd probably want to cache it
        self.vars = self.get_fops_vars()

    def get_fops_types(self) -> list:
        """Get `fops` types.
        fops is this context means a kernel control record containing function
        pointers for dispatching user-requested operations in the kernel,
        so things like, most notably, struct file_operations or struct proc_ops.

        Because FTDB generates different type entries for a singular type
        (for example, const and non-const type usages generate two different type
        entries in FTDB, with different ids), we want to collect them all with
        filtering by name.

        Unfortunately, there might be cases when various versions of one type
        appear in which case, we maintain an array of names for each detected fop,
        so that we can detect which one we use in a case by it's ID and retrieve
        a function pointer pointee correctly

        :returns: array of FTDB dict-like type entry
        """
        # We want a full record definition, not a forward one
        fops_types = [x for x in self.ftdb['types']
                      if x['str'] in self.FILE_OPERATIONS
                      and x['class'] != 'record_forward']
        if not len(fops_types):
            raise AttributeError('Could not find struct file_operations given \
                                  in given database')
        return fops_types

    def get_fops_vars(self) -> list:
        """Get instances of all detected fops types

        :returns: list of FTDB fops instances of types
        deducted to be accepted by syzdescriptor.
        """
        fops_ids = [x['id'] for _, v in self.types.items() for x in v]
        return [x for x in self.ftdb['fops'] if x['type'] in fops_ids]

    def find_new_fops_name(self, fops: dict[str, int], name: str) -> str:
        """Generate a new, unique name for given fops names

        Often times fops variable instance names are similar, there are various
        non-global names that are identical, hence we need to rename them sometimes

        :param fops: Dictionary whose keys are names of already collected fops
        :param name: Currently proposed name for new fop, it does not have
                            to be unique and will be mutated
        :returns: New, unique name to be used instead of @name
        """
        while name in fops.keys():
            name += '_'
        return name

    def collect_fops(self, fops_type: str, name: str) -> list[Fops]:
        """Collect fops instances which contain a given handler

        :param name: Name of a handler we want to capture
        :returns: List of Fops objects
        """
        fops = dict()
        for var in [x for x in self.vars if self]:
            if self.ftdb['types'].entry_by_id(var['type']) != fops_type:
                continue

            for field_id, func_id in var['members'].items():
                field_id = int(field_id)
                func_id = func_id[0]
                fields = self.fields[var['type']]

                fop_type = fields[field_id] \
                           if len(fields) >= field_id + 1 else None

                if not fop_type:
                    continue

                # TODO: This fopsEntry does not actually have to be a global.
                # It can be worked out for locals as well but I just didn't do
                # it for now.
                if fop_type == name \
                    and self.ftdb['funcs'].contains_id(func_id) \
                    and var['kind'] == 'global':
                    fops_name = self.ftdb['globals'][var['var']]['name']
                    if fops.get(fops_name):
                        fops_name = self.find_new_fops_name(fops, fops_name)
                    fops[fops_name] = Fops(fops_name, func_id)

        return list(fops.values())

class BasePass:
    """Base abstract class for any other pass implementations.
    """

    @abc.abstractmethod
    def process(self, fops: Fops) -> bool:
        """Abstract function (as much as Python has those) for interfaces
        used as entry point when analyzing from the top-level
        generate_descriptions() function

        Yes, this function does absolutely nothing. This is more of a hint to the
        developer that this function should be overriden when you want to create
        an analyzer.

        :param fops: Fops object
        """
        raise NotImplementedError('Class derived from BasePass has had \
an overriden process() called on')

class IoctlAnalysisPass(BasePass):
    """Ioctl kernel function analyzer.

    Here goes on probably the most gimmicky code in syzdescriptor.
    What we are mostly interested in when we generate syzkaller descriptions is
    IOCTL commands and types of their arguments.

    These are mostly encoded in IOR/IOW/IOWR macros, their unexpanded definitions
    contain sizeof of the argument type (if we trust the developer to be nice enough
    and provide them true to the practical usage)

    This module looks ioctls with switch/case's and tries to extract those to reliably
    provide a root types needed for each command.
    """

    """This is the FTDB way of representing arguments passed to a `callref`
    which is a term for references to resources of your function passed to a
    certain call.

    These are the positions of arguments passed to the original ioctl handler.
    """
    IOCTL_FILE_ARG     = ('parm', 0)
    IOCTL_COMMAND_ARG  = ('parm', 1)
    IOCTL_ARGUMENT_ARG = ('parm', 2)

    """Wonderful regex.

    Because FTDB has currently no way of getting type information of sizeof
    operators, we need to do it in a more primitive way.
    After determining that a function has a switch/case on the ioctl command
    argument, we check the case values for non-expanded macros and see
    if we can extract a typename of it
    """
    SIZEOF_REGEX = r'sizeof\(([a-zA-Z0-9\s_\-$\[\]\*]+)\)'

    """
    Forward declaration have a separate type definition, we should ignore them,
    this is basically an ignore list of what types we avoid when searching
    for a desired type by name in FTDB
    """
    FORWARD_DECLARED_TYPES = [
        'record_forward',
        'enum_forward'
    ]

    ftdb: libftdb.ftdb

    def __init__(self, ftdb: libftdb.ftdb):
        self.ftdb = ftdb

    def pick_switchcases_by_argument_name(self, fid: int, condition) \
        -> list['libftdb.ftdbSwitchInfo']:
        """Get a list of switch objects of condition matching @argument_condition

        :param fid: FTDB function id of the function to search
        :returns: List of FTDB switch objects
        """
        switches = []
        function = self.ftdb['funcs'].entry_by_id(fid)

        for switch in function['switches']:
            if switch['condition'] == condition:
                switches.append(switch)

        return switches

    def get_forwarded_ioctls(self, fid: int) -> list[tuple[int, int]]:
        """Get a list of functions to which @fid function could've possibly
        delegated ioctl handling

        There are cases in some drivers where the original ioctl handler is just
        a wrapper for the actual ioctl handling logic.
        This heurestic helps us find the function that actually deals with
        handling the ioctl.

        :param fid: FTDB function id of the target function
        :returns: List of tuples in format
        (call index, command parameter in the called function)
        """
        candidates = list()
        function = self.ftdb['funcs'].entry_by_id(fid)

        for i in range(len(function['callrefs'])):
            callref = function['callrefs'][i]
            typeparams = [(ref['type'], ref['id']) for ref in callref]
            typepos = [ref['pos'] for ref in callref]

            if self.IOCTL_COMMAND_ARG in typeparams \
                and self.IOCTL_ARGUMENT_ARG in typeparams:
                candidates.append((function['calls'][i], \
                                   typepos[typeparams.index(self.IOCTL_COMMAND_ARG)]))
        return candidates

    def recursively_pick_ioctl_with_switchcase(self,
                                               fid: int,
                                               argument_id: int = 1,
                                               depth: int = 1,
                                               max_depth: int = 3) -> list:
        """Recursively look for functions with switch cases on @argument_id
        taking into the account changed possition on @argument_id in subsequent
        calls.

        High-level function aggregating pick_switchcases_by_argument_name
        and recursively_pick_ioctl_with_switchcase. Look at their documentation.

        :param fid: FTDB function id of the root function
        :param argument_id: Index of the condition parameter in arguments for
        @fid function
        :param depth: Current recurse depth
        :param max_depth: Max recurse depth
        """
        functions = []

        if depth > max_depth:
            return functions

        try:
            function = self.ftdb['funcs'].entry_by_id(fid)
            argument_name = function['locals'][argument_id]['name']
        except Exception:
            # We may go too deep and find an assembly stub, which is not in funcs
            # or go out of bound if function has variadic arguments
            return functions

        targeted_switch = self.pick_switchcases_by_argument_name(fid, argument_name)
        if targeted_switch:
            functions.append((fid, argument_id))

        for candidate_id, argument_id in self.get_forwarded_ioctls(fid):
            functions.extend(self.recursively_pick_ioctl_with_switchcase(candidate_id, \
                                                                         argument_id, \
                                                                         depth + 1, \
                                                                         max_depth))

        return functions

    def __strip_type(self, type_name: str) -> tuple[str, str]:
        """Return just the type name, without type qualifiers

        Needed for searching FTDB types by name

        :param type_name: Full C type name, pulled out of sizeof()
        :returns: Tuple in format (stripped name, deducted typekind)
        """
        if type_name.startswith('struct '):
            name = type_name.split('struct ')[-1]
            if type_name.endswith(' *'):
                name = name.split(' *')[0]
            return name, 'record'
        elif type_name.startswith('union '):
            name = type_name.split('union ')[-1]
            if type_name.endswith(' *'):
                name = name.split(' *')[0]
            return name, 'record'
        elif type_name.startswith('enum '):
            name = type_name.split('enum ')[-1]
            if type_name.endswith(' *'):
                name = name.split(' *')[0]
            return name, 'enum'
        elif type_name.endswith(' *'):
            return type_name.split(' *')[0], 'pointer'
        elif type_name.endswith(' ['):
            name = type_name.split(' [')[0]
            rest = type_name.split(' [')[-1]
            if rest.startswith(']') or rest.startswith('0]'):
                return name, 'incomplete_array'
            else:
                return name, 'const_array'
        else:
            return type_name, 'builtin'

    def __get_ftdb_type_id_from_string(self, type_name: str) -> Optional[int]:
        """Get FTDB type ID of type called @type_name

        Another heurestic. FTDB, rightfully so, does not implement searching types
        by name because they often repeat.
        For this reason, we might find a type which does not match the actually
        used type.
        We also skip forward declared type entries.

        :param type_name: Name of a type to find.
        :returns: Guessed FTDB type id
        """
        identifier, _ = self.__strip_type(type_name)

        found_types = [x for x in self.ftdb['types'] if x['str'] == identifier]
        try:
            guessed_type = [x for x in found_types
                            if x['class'] not in self.FORWARD_DECLARED_TYPES][0]
        except IndexError:
            return None

        return guessed_type['id']

    def analyze_switch_cases(self, fid: int) -> set[tuple[str, int, int]]:
        """Get a list of tuples of used case labels, evaluated macros and guessed
        types

        This analyzes a root function of @fid id and its subsequent calls to which
        it potentially can delegate ioctl handling to.
        The function return complete information about a function for generating
        a syzlang syscall definition (minus open paths, this is done later on).

        :param fid: FTDB function id
        :returns: set of tuples in format
        (used case expression, evaluated case expression, type for this command)
        """
        cases = set()

        functions = self.recursively_pick_ioctl_with_switchcase(fid)
        if not functions:
            return cases

        for function_id, argument_id in functions:
            function = self.ftdb['funcs'].entry_by_id(function_id)
            argument_name = function['locals'][argument_id]['name']
            switches = self.pick_switchcases_by_argument_name(function['id'], \
                                                              argument_name)
            if not switches:
                return cases

            for case in [y for x in switches for y in x['cases']]:
                case_value = case[0]
                case_label = case[2]
                unwinded_case = case[3]

                captures = re.search(self.SIZEOF_REGEX, unwinded_case)
                if not captures:
                    continue

                type_name = captures.groups()[0]

                type_id = self.__get_ftdb_type_id_from_string(type_name)
                if not type_id:
                    continue

                cases.add((case_label, case_value, type_id))

        return cases

    # @TODO
    def analyze_ifs(self, fid: int) -> set:
        return set()

    def analyze_ioctl_commands(self, fid: int) -> set[tuple[str, int, int]]:
        """Perform ioctl command analysis.

        See IoctlPass.analyze_switch_cases() for more informations

        :param fid: FTDB function id
        :returns: List of tuples in format
        (used case expression, evaluated case expression, type for this command)
        """
        return self.analyze_switch_cases(fid).union(self.analyze_ifs(fid))

    def process(self, fops: Fops) -> bool:
        """Perform ioctl command analysis.

        See IoctlPass.analyze_switch_cases() for more informations

        :param fops: Fops object
        :returns: True if found any ioctl commands, False otherwise
        """
        fops.commands = self.analyze_ioctl_commands(fops.syscall_id)

        return len(fops.commands) > 0

class TypeAnalysisPass(BasePass):
    """Pass for proper type graph extraction for a passed root.

    Type dependencies make a cyclic graph, syzdescriptor needs to extract an
    acyclic dependency graph for a given root type.

    There are other rules as well, we don't care about typedef type definitons,
    which have separate definitions, or pointer types.

    For a full description, for every typedef, pointer or forward declaration,
    syzdescriptor needs to extract a concrete declaration of this type.
    """
    ftdb: libftdb.ftdb

    def __init__(self, ftdb: libftdb.ftdb):
        self.ftdb = ftdb

    def detypedef(self, type_id: int) -> int:
        """Recursively find concrete type definition for given @type_id

        :param type_id: FTDB type id
        :returns: Detypedefed FTDB type id
        """
        db_type = self.ftdb['types'].entry_by_id(type_id)

        while db_type['class'] == 'typedef':
            db_type = self.ftdb['types'].entry_by_id(db_type['refs'][0])

        return db_type['id']

    def __find_unique_type_dependencies(self, type_id: int, found: set[int]) -> set[int]:
        if type_id in found:
            return found

        db_type = self.ftdb['types'].entry_by_id(type_id)
        found.add(type_id)

        if db_type['class'] == 'enum':
            return found

        for ref in db_type['refs']:
            self.__find_unique_type_dependencies(self.detypedef(ref), found)

        return found

    def find_unique_type_dependencies(self, type_id: int) -> set[int]:
        """Find unique dependencies for a given type id

        :param type_id: FTDB type ID of entry type, can be a typedef
        :returns: Set of FTDB type ids which are unique/acyclic
        dependencies of gived concrete type for type_id
        """
        return self.__find_unique_type_dependencies(self.detypedef(type_id), set())

    def contains_fields(self, type_id: int) -> bool:
        """Type references predicate, returns the amount of type references for
        passed @type_id

        :param type_id: FTDB type id to check for ref count
        :returns: True if amount of type references for passed @type_id
        is greater than 0, False otherwise
        """
        return len(self.ftdb['types'].entry_by_id(self.detypedef(type_id))['refs']) > 0

    def dereference(self, type_id: int) -> int:
        """Recursively find concrete type definition or referenced type under
        pointer for given @type_id

        :param type_id: FTDB type id
        :returns: Detypedefed and dereferenced FTDB type id
        """
        db_type = self.ftdb['types'].entry_by_id(type_id)

        while db_type['class'] in ['pointer', 'typedef']:
            db_type = self.ftdb['types'].entry_by_id(db_type['refs'][0])

        return db_type['id']

    def process(self, fops: Fops) -> bool:
        """Extract unique type graphs for each command.

        IMPORTANT: This stage can only run after IoctlPass.

        See BasePass.process()

        :param fops: Fops object
        :returns: True if found any types, False otherwise
        """
        if not hasattr(fops, 'commands'):
            raise AttributeError('Prerequisite commands for {} are not \
defined. Remember to run IoctlPass \
prior to running TypePass'.format(fops.syscall_id))

        fops.deps = set(filter(
            self.contains_fields,
            [x for _, _, type_id in fops.commands
               for x in self.find_unique_type_dependencies(type_id)]
        ))

        return len(fops.deps) > 0

class PointerCyclesPass(TypeAnalysisPass):
    """Helper analyzer for finding pointer cycles in the type dependency graph
    """
    def __init__(self, ftdb: libftdb.ftdb):
        super().__init__(ftdb)

    def __analyze_pointer_cycles(self, type_id: int, traversed: set[int]) -> dict[int, list[PointerCycle]]:
        cycles = dict()

        if type_id in traversed:
            return cycles

        db_type = self.ftdb['types'].entry_by_id(type_id)
        if db_type['class'] != 'record':
            return cycles

        for i in range(len(db_type['refs'])):
            # We only care about cycles with a pointer indirection
            ref_type = self.ftdb['types'].entry_by_id(db_type['refs'][i])
            if ref_type['class'] != 'pointer':
                continue

            derefed = self.dereference(db_type['refs'][i])
            if derefed in traversed:
                if fields := cycles.get(type_id):
                    fields.append(PointerCycle(derefed, i))
                else:
                    cycles[type_id] = [PointerCycle(derefed, i)]

        traversed.add(type_id)

        for ref in db_type['refs']:
            if ref in traversed:
                continue
            cycles = { **cycles,
                      **self.__analyze_pointer_cycles(self.dereference(ref),
                                                      traversed) }

        return cycles

    def analyze_pointer_cycles(self, type_id: int) -> dict[int, list[PointerCycle]]:
        """Find and return list of record fields which loop back to some type higher
        in the graph.

        Those fields shall be marked as ptr[..., opt] during syzlang generation.
        Otherwise, the syzlang compiler will scream at you.

        :param type_id: FTDB type id to recursively analyze for type cycles
        :returns: Dict mapping FTDB type ids to
        a list of pointer cycles within its fields
        """
        return self.__analyze_pointer_cycles(self.detypedef(type_id), set())

    def process(self, fops: Fops) -> bool:
        """Analyze pointer cycles.

        IMPORTANT: This analyzer has to run after IoctlPass.

        See PointerCyclesPass.analyze_pointer_cycles for more.
        :param fops: Fops object
        :returns: True
        """
        if not hasattr(fops, 'commands'):
            raise AttributeError('Prerequisite commands for {} are not \
defined. Remember to run IoctlPass \
prior to running PointerBoundPass'.format(fops.syscall_id))

        fops.pointer_cycles = dict()
        for _, _, type_id in fops.commands:
             fops.pointer_cycles = { **fops.pointer_cycles,
                                     **self.analyze_pointer_cycles(type_id) }

        return True

class PointerBoundsPass(BasePass):
    """Pass for so called pointer bounds.

    This is my own term, maybe I should change it, but I found it fitting in this
    case. Pointer bounds is a more narrow synonym to mutually dependant types.

    A record may contain two fields which are mutually dependant, most notably
    in our line of work, this is often a pointer + size pair (hence the name
    pointer bounds, the pointer is heurestically bound to its size)

    We want to detect such cases in order to generate better recipes for syzkaller.

    This is currently done by inspecting a range of functions for uaccess calls
    described in @BINDING_CALLS, checking whether they operate on a coloured,
    user-provided data.

    If one of the operands and the size argument come from user-provided data, then
    we can safely say that they are bound together and tag them as such in the
    generated description.
    """

    """Dictionary of functions that can tell us the bounds.
    It maps function names to an array of dicts in format:
    { 'binding': <int>, 'bound': <int> }

    'binding' describes a position of size argument of this function and
    'bound' describes a position of pointer argument for this function
    associated with this size.

    There might be more than one for each function, hence the array usage.
    """
    BINDING_CALLS = {
        'copy_from_user': [
            { 'binding': 2, 'bound': 0 },
            { 'binding': 2, 'bound': 1 }
        ],
        'copy_to_user': [
            { 'binding': 2, 'bound': 0 },
            { 'binding': 2, 'bound': 1 }
        ],
    }

    def __init__(self, ftdb: libftdb.ftdb):
        self.ftdb = ftdb

        self.id_to_name = dict()
        for func_name in self.BINDING_CALLS.keys():
            ids = self.ftdb['funcs'].entry_by_name(func_name)

            for function_object in ids:
                self.id_to_name[function_object['id']] = func_name

    def __find_indexes_of_element(self, lst: list, element):
        return [i for i in range(len(lst)) if lst[i] == element]

    def analyze_bounds(self, func_id: int, depth: int = 1, max_depth: int = 4) -> dict[int, list[MemberBounds]]:
        """Analyzes pointer bounds

        See PointerBoundsPass class documentation

        :param func_id: FTDB function id
        :param depth: current recurse depth
        :param max_depth: maximal recurse depth
        :returns: dict mapping FTDB type ID to a list of fields that are deducted
        to be dependant
        """
        res = dict()

        try:
            db_func = self.ftdb['funcs'].entry_by_id(func_id)
        except Exception:
            return res

        call_indexes = [x
            for fid in self.id_to_name.keys()
            for x in self.__find_indexes_of_element(db_func['calls'], fid)]

        if depth > max_depth or not len(call_indexes):
            return res

        derefs = db_func['derefs']
        call_info = db_func['call_info']
        for call_index in call_indexes:
            models = self.BINDING_CALLS[
               self.id_to_name[db_func['calls'][call_index]]
            ]

            for model in models:
                binding_deref = derefs[
                    call_info[call_index]['args'][model['binding']]
                ]

                bound_deref = derefs[
                    call_info[call_index]['args'][model['bound']]
                ]

                # Here we outright discard any other deref kinds
                # If a parameter is a callref, it can return a deref to a member
                # This case should be analyzed
                if binding_deref['offsetrefs'][0]['kind'] != 'member' or \
                   bound_deref['offsetrefs'][0]['kind'] != 'member':
                    continue

                while binding_deref['kind'] != 'member' or \
                      bound_deref['kind'] != 'member':

                    if binding_deref['kind'] != 'member':
                        binding_deref = db_func['derefs'][
                            binding_deref['offsetrefs'][0]['id']
                        ]

                    if bound_deref['kind'] != 'member':
                        bound_deref = db_func['derefs'][
                            bound_deref['offsetrefs'][0]['id']
                        ]

                # Assure that we are binding only members within the same record
                if binding_deref['type'][-1] != bound_deref['type'][-1]:
                    continue

                # Something wrong happens if union is parent type of bound pointer
                # Skip it for now
                anchor_record = self.ftdb['types'] \
                    .entry_by_id(bound_deref['type'][-1])
                if anchor_record['class'] == 'record' and \
                   anchor_record['union'] is True:
                    continue

                member_bounds = MemberBounds(bound_deref['type'][-1],
                                 binding_deref['member'][-1],
                                 bound_deref['member'][-1])

                if res.get(bound_deref['type'][-1]):
                    res[bound_deref['type'][-1]].add(member_bounds)
                else:
                    s = set()
                    s.add(member_bounds)
                    res[bound_deref['type'][-1]] = s

        for call in db_func['calls']:
            res = { **res, **self.analyze_bounds(call, depth + 1) }

        return res

    def process(self, fops: Fops) -> bool:
        """Analyzes pointer bounds

        See PointerBoundsPass class documentation

        :param fops: Fops object
        :returns: True
        """
        fops.pointer_bounds = self.analyze_bounds(fops.syscall_id)

        return True
