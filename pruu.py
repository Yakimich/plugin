from typing import Any, Callable, Iterable, List

from volatility3.framework import interfaces, renderers, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.linux.extensions import elf
from volatility3.plugins.linux import elfs

class ProcessUnderUserPlugin(interfaces.plugins.PluginInterface):
    """Plugin to detect anomalous activity related to running a system process from under a user"""
    _required_framework_version = (2, 0, 0)

    _version = (2, 1, 0)
    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            # Define the plugin requirements
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="elfs",
                plugin=elfs.Elfs,
                version=(2, 0, 0)
            ),
            requirements.BooleanRequirement(
                name="include_threads",
                description="Include user threads",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="decorate_comm",
                description="Decorate comm string for user threads in curly brackets and kernel threads in square brackets",
                optional=True,
                default=False,
            ),
            requirements.BooleanRequirement(
                name="dump",
                description="Extract listed processes",
                optional=True,
                default=False,
            ),
        ]

    @classmethod
    def create_pid_filter(cls, pid_list: List[int] = None) -> Callable[[Any], bool]:
        """Constructs a filter function for process IDs.

        Args:
            pid_list: List of process IDs that are acceptable (or None if all are acceptable)

        Returns:
            Function which, when provided a process object, returns True if the process is to be filtered out of the list
        """
        pid_list = pid_list or []
        filter_list = [x for x in pid_list if x is not None]
        
        if filter_list:
            def filter_func(x):
                return x.pid not in filter_list
            return filter_func
        else:
            return lambda _: False

    def _generator(
        self,
        pid_filter: Callable[[Any], bool],
        include_threads: bool = False,
        decorate_comm: bool = False,
        dump: bool = False,
    ) -> Iterable[tuple[int, tuple[Any, ...]]]:
        tasks = self.list_tasks(self.context, self.config["kernel"], pid_filter, include_threads)
        elf_table_name = intermed.IntermediateSymbolTable.create(
            self.context,
            self.config_path,
            "linux",
            "elf",
            class_types=elf.class_types,
            #table_mappings=elf.ELF32.CLASS_TYPE_MAPPINGS,
        )

        for task in tasks:
            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            if dump:
                file_output = "Error outputting file"
                for v in task.mm.get_mmap_iter():
                    if v.vm_start == task.mm.start_code:
                        file_handle = elfs.Elfs.elf_dump(
                            self.context,
                            proc_layer_name,
                            elf_table_name,
                            v,
                            task,
                            self.open,
                        )
                        if file_handle:
                            file_output = str(file_handle.preferred_filename)
                            file_handle.close()
                        break
            else:
                file_output = "Disabled"

            pid = task.tgid
            tid = task.pid
            ppid = task.parent.tgid if task.parent else 0
            name = utility.array_to_string(task.comm)
            
            if decorate_comm:
                if task.is_kernel_thread:
                    name = f"[{name}]"
                elif task.is_user_thread:
                    name = f"{{{name}}}"
                
            yield (0, (format_hints.Hex(task.vol.offset), pid, tid, ppid, name, file_output))

    @classmethod
    def list_tasks(
        cls,
        context: interfaces.context.ContextInterface,
        vmlinux_module_name: str,
        filter_func: Callable[[int], bool] = lambda _: False,
        include_threads: bool = False,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
        vmlinux = context.modules[vmlinux_module_name]
        init_task = vmlinux.object_from_symbol(symbol_name="init_task")

        for task in init_task.tasks:
            if filter_func(task):
                continue

            yield task

            if include_threads:
                yield from task.get_threads()

    def run(self):
        pids = self.config.get("pid")
        include_threads = self.config.get("include_threads")
        decorate_comm = self.config.get("decorate_comm")
        dump = self.config.get("dump")

        filter_func = self.create_pid_filter(pids)

        columns = [
            ("OFFSET (V)", format_hints.Hex),
            ("PID", int),
            ("TID", int),
            ("PPID", int),
            ("COMM", str),
            ("File output", str),
        ]

        return renderers.TreeGrid(columns, self._generator(filter_func, include_threads, decorate_comm, dump))
