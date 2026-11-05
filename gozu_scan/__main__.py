import sys

from .run import gate, main

sys.exit(gate() if sys.argv[1:] == ["gate"] else main())
