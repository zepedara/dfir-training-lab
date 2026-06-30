# -*- coding: utf-8 -*-
# Make appSearch's known-bad/non-indexed search run on Windows. The Producer/Consumer are
# multiprocessing.Process subclasses; .start() spawns children that die on Windows 'spawn'
# (pickle EOF). Their queues/Values all work in a single process, so on Windows we call
# .run() inline (no spawn, no pickle) -- producers drain tasks then consumers drain results.
import io, os, py_compile

p = r"C:\DFIR\tools\appcompatprocessor\appSearch.py"
s = io.open(p, "rb").read()
bak = p + ".serialbak"
if not os.path.exists(bak):
    io.open(bak, "wb").write(s)

if b"os.name == 'nt' else producer.start" not in s:
    if b"import os" not in s:
        s = s.replace(b"import multiprocessing", b"import os\nimport multiprocessing", 1)
    s = s.replace(b"num_producers = max(1, maxCores - 1)",
                  b"num_producers = 1 if os.name == 'nt' else max(1, maxCores - 1)")
    s = s.replace(b"            producer.start()",
                  b"            (producer.run() if os.name == 'nt' else producer.start())")
    s = s.replace(b"            consumer.start()",
                  b"            (consumer.run() if os.name == 'nt' else consumer.start())")
    s = s.replace(b"            consumer.join()",
                  b"            (None if os.name == 'nt' else consumer.join())")
    io.open(p, "wb").write(s)
    print("appSearch patched")
else:
    print("appSearch already patched")

py_compile.compile(p, doraise=True)
print("COMPILE OK")
