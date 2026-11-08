"""Entry point for `python -m depwatch`.

When you run `python -m depwatch ...`, Python looks for this file inside the
package and runs it. All it does is hand control to the CLI and pass the CLI's
exit code back to the operating system.
"""

import sys

from depwatch.cli import main

# sys.exit() sends the number returned by main() back to the shell
# (0 = ok, 1 = vulnerabilities found, 2 = scan incomplete / bad input).
sys.exit(main())
