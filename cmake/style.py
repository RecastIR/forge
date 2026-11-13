"""Format Forge-owned sources and locate changed lines for advisory lint checks."""
import os
from pathlib import Path
import re
import subprocess
import sys
from xml.etree import ElementTree


NATIVE_ROOTS = ('src', 'tests/support', 'tests/unit')
ROOTS = (*NATIVE_ROOTS, 'tests/fixtures', 'tests/differential/fixtures', 'tests/differential/reference')
EXCLUDED = {'generated', 'vendor', 'vendored', 'third_party', 'third-party', 'external', '_deps', 'CMakeFiles'}
HUNK = re.compile(rb'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@', re.MULTILINE)


def git(*args):
    return subprocess.check_output(['git', '--literal-pathspecs', *args])


def owned(path):
    return (path.suffix in {'.h', '.cpp', '.c'} and any(Path(root) in path.parents for root in ROOTS)
            and not any(p in EXCLUDED or p == 'build' or p.startswith(('build-', 'cmake-build-'))
                        for p in path.parts[:-1]))


def regular_source(path):
    return owned(path) and path.is_file() and path.resolve() == Path.cwd() / path


def sources():
    names = git('ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', *ROOTS)
    paths = (Path(os.fsdecode(name)) for name in names.split(b'\0') if name)
    return sorted({path for path in paths if regular_source(path)})


def comparison_base():
    ref = os.environ.get('FORGE_STYLE_BASE')
    try:
        if ref:
            return git('rev-parse', '--verify', '--end-of-options', ref + '^{commit}').decode().strip()
        return git('merge-base', 'HEAD', 'origin/main').decode().strip()
    except subprocess.CalledProcessError:
        raise SystemExit(f'Cannot resolve style base {ref or "(merge base with origin/main)"}. '
                         'Fetch its Git history or set FORGE_STYLE_BASE to an available base commit.')


def changed_sources():
    """Return inclusive working-tree line ranges, or None for a whole new file."""
    base = comparison_base()
    fields = iter(git('diff', '--name-status', '-z', '--find-renames', '--no-ext-diff',
                      base, '--', *ROOTS).split(b'\0'))
    changes = {}
    for status in fields:
        if not status:
            break
        old = Path(os.fsdecode(next(fields)))
        path = Path(os.fsdecode(next(fields))) if status.startswith(b'R') else old
        if status == b'U':
            raise SystemExit(f'{path}: resolve the Git conflict before running style checks.')
        if status == b'D' or not regular_source(path):
            continue
        if status in (b'A', b'T') or not owned(old):
            changes[path] = None
            continue
        patch = git('diff', '--text', '--no-color', '--no-ext-diff', '--no-textconv', '-U0',
                    '--inter-hunk-context=0', f'{base}:{old}', '--', str(path))
        ranges = []
        for start, count in HUNK.findall(patch):
            line, length = int(start), int(count or 1)
            # A deletion can join tokens or remove standalone braces. Check the seam.
            ranges.append((max(1, line), line + (length - 1 if length else 1)))
        if ranges:
            changes[path] = ranges
    for name in git('ls-files', '-z', '--others', '--exclude-standard', '--', *ROOTS).split(b'\0'):
        if name and regular_source(path := Path(os.fsdecode(name))):
            changes[path] = None
    return changes


def native(path):
    return any(Path(root) in path.parents for root in NATIVE_ROOTS) and path.suffix in {'.cpp', '.h'}


def fixture_brace_lines(tool, path):
    # Windows fixtures use a separate toolchain. Probe the formatter's proposed
    # brace insertions without rewriting the file or requiring Windows headers.
    data = path.read_bytes()
    xml = subprocess.check_output([tool, '--output-replacements-xml', '--fail-on-incomplete-format',
                                   '--style={BasedOnStyle: InheritParentConfig, InsertBraces: true}',
                                   f'--assume-filename={path}'], input=data)
    for node in ElementTree.fromstring(xml).findall('replacement'):
        offset, size = int(node.attrib['offset']), int(node.attrib['length'])
        if (node.text or '').count('{') > data[offset:offset + size].count(b'{'):
            yield data.count(b'\n', 0, offset) + 1


def format_sources(action, tool):
    paths = sources()
    if not paths:
        return 0
    command = [tool, '--style=file', '--fail-on-incomplete-format']
    if action == 'format':
        return subprocess.run([*command, '-i', *paths]).returncode

    failed = subprocess.run([*command, '--dry-run', '--Werror', *paths]).returncode != 0
    if failed:
        print('Run make format to correct formatting.', file=sys.stderr)
    for path in paths:
        if not native(path):
            for line in sorted(set(fixture_brace_lines(tool, path))):
                print(f'{path}:{line}: add braces to the control-flow body.', file=sys.stderr)
                failed = True
    return int(failed)


if __name__ == '__main__':
    if sys.argv[1] == 'native-sources':
        for path in sources():
            if native(path) and path.suffix == '.cpp':
                print(path.absolute())
    else:
        sys.exit(format_sources(*sys.argv[1:]))
