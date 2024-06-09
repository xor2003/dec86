#!/usr/bin/env python3
import sys

import angr
from angr.analyses import CFGFast, VariableRecoveryFast, CallingConventionAnalysis, Decompiler

from angr_platforms.X86_16.lift_86_16 import Lifter86_16  # noqa
from angr_platforms.X86_16.simos_86_16 import SimCC8616MSC  # noqa



#logging.getLogger('angr').setLevel('DEBUG')
#logging.getLogger('angr.calling_conventions').setLevel('DEBUG')
#logging.getLogger('pyvex.lifting.util').setLevel('DEBUG')
#logging.getLogger('angr_platforms.angr_platforms.X86_16.lift_86_16').setLevel('DEBUG')


#arch_32 = ArchX86()  # get architecture
project = angr.Project(sys.argv[1], auto_load_libs=False)
print("After load")

#block = project.factory.block(project.entry, max_size=len(byte_string))

print("After disasm")
# force_complete_scan=False - because it is mix of code and data
cfg = project.analyses[CFGFast].prep()(force_complete_scan=False, data_references=True, normalize=True)

for node in cfg.graph.nodes():
    block = project.factory.block(node.addr, size=node.size)
    if block.size == 0:
        continue
    print(f"Block at {hex(node.addr)}, size: {block.size}")

    block.pp()
    block.vex.pp()
    print()

for addr, func in cfg.functions.items():
        _ = project.analyses[VariableRecoveryFast].prep()(func)
        cca = project.analyses[CallingConventionAnalysis].prep()(func, cfg=cfg.model)
        func.calling_convention = cca.cc
        func.prototype = cca.prototype
        
        dec = project.analyses[Decompiler].prep()(func, cfg=cfg.model)
        assert dec.codegen is not None, "Failed to decompile function %s." % repr(func)
        print("Decompiled function %s\n%s" % (repr(func), dec.codegen.text))
