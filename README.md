# hslint

A Haskell Static Analysis Tool implemented in Python

Checks for:
- Unsafe use of unsafePerformIO
- Unsafe use of IO
- Partial pattern match
- Potential resource leak (open without close)