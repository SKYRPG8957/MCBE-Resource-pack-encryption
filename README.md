# MCBE-Resource pack encryption
형석 존잘


## Regression tests

With Python 3.10+ and `pycryptodome` installed, run from the repository root:

```sh
python -m unittest discover -s tests -v
```

The tests exercise the Python encryption backend and decrypt generated metadata
and file data to verify round trips. ZIP files may omit directory entries;
subpacks are discovered from `subpacks/<name>/...` member paths as well as
explicit directories. Files immediately inside `subpacks/` are preserved in
the root content index. These tests do not replace an in-game Bedrock check
or exercise the separate browser JavaScript implementation.
