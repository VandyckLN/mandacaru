"""`python -m mandacaru`: o mesmo que o comando `mandacaru`."""
import sys

from .cli import main

sys.exit(main())
