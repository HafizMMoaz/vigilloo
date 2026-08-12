"""Blade template rewriting.

Blade is not PHP. Laravel compiles it; Vigilloo rewrites it into a normalised
form the PHP grammar can read, preserving the escaping mode of every echo,
because that distinction is the XSS rule - see docs/03-parser.

The transformation is line-preserving: output line N came from input line N.
That is what lets evidence paths cite real .blade.php line numbers with no
mapping table to drift out of sync. Columns are not preserved, which is
accepted: reports render a line number and a snippet, and the snippet is taken
from the original Blade text.

Surrounding markup is left alone rather than blanked. The text-mode PHP grammar
treats anything outside <?php ... ?> as inert, so each rewritten echo is an
island in text the parser already ignores.

ponytail: regex-level rewriting, not a Blade parser. Handles the echo forms,
comments and @php blocks, which is what this slice's rules reach. If this hits
@verbatim or deeply nested directives, vendoring EmranMR/tree-sitter-blade is
the escape hatch - see the slice 2 design.
"""

import re

# Order matters. Comments are stripped before echoes so a commented-out echo
# does not become a sink. The literal @{{ form is protected before {{ is
# rewritten, or a JS template would be analysed as PHP.
_COMMENT = re.compile(r"\{\{--.*?--\}\}", re.S)
_LITERAL = re.compile(r"@\{\{.*?\}\}", re.S)
_RAW_ECHO = re.compile(r"\{!!(.*?)!!\}", re.S)
_ESCAPED_ECHO = re.compile(r"\{\{(.*?)\}\}", re.S)
_PHP_BLOCK = re.compile(r"@php(.*?)@endphp", re.S)
_SCRIPT_BLOCK = re.compile(r"<script.*?>.*?</script>", re.S | re.IGNORECASE)

_INCLUDE = re.compile(r"@include(?:If|When|Unless)?\s*\((.*?)\)", re.S)
_EXTENDS = re.compile(r"@extends\s*\((.*?)\)", re.S)
_COMPONENT_DIRECTIVE = re.compile(r"@component\s*\((.*?)\)", re.S)
_COMPONENT_TAG = re.compile(r"<x-([a-zA-Z0-9_\.-]+)(\s+[^/>]*)?(?:/>|>(.*?)</x-\1>)", re.S)

_FOREACH = re.compile(r"@foreach\s*\((.*?)\)", re.S)
_ENDFOREACH = re.compile(r"@endforeach", re.S)
_FORELSE = re.compile(r"@forelse\s*\((.*?)\)", re.S)
_EMPTY = re.compile(r"@empty", re.S)
_ENDFORELSE = re.compile(r"@endforelse", re.S)
_FOR = re.compile(r"@for\s*\((.*?)\)", re.S)
_ENDFOR = re.compile(r"@endfor", re.S)
_WHILE = re.compile(r"@while\s*\((.*?)\)", re.S)
_ENDWHILE = re.compile(r"@endwhile", re.S)

_LITERAL_PLACEHOLDER = "\x00vigilloo-blade-literal\x00"


def _keep_lines(replacement: str, matched: str) -> str:
    """Pad a replacement so it spans as many lines as the text it replaced.

    Only the shortfall is added. The echo and @php replacements splice the
    captured expression back in verbatim, so they already carry that
    construct's own newlines; padding by the full count would double them
    and push every later line down.
    """
    deficit = matched.count("\n") - replacement.count("\n")
    return replacement + "\n" * max(deficit, 0)


def _parse_component_attrs(attrs_text: str) -> str:
    if not attrs_text:
        return ""
    pairs: list[str] = []
    pattern = re.compile(r'(:?)([a-zA-Z0-9_-]+)=(?:"([^"]*)"|\'([^\']*)\'|(\S+))')
    for m in pattern.finditer(attrs_text):
        is_bound, name, v_double, v_single, v_raw = m.groups()
        val = v_double if v_double is not None else (v_single if v_single is not None else v_raw)
        if is_bound:
            pairs.append(f"'{name}' => {val}")
        else:
            pairs.append(f"'{name}' => '{val}'")
    if not pairs:
        return ""
    return ", [" + ", ".join(pairs) + "]"


def _rewrite_component_tag(match: re.Match[str]) -> str:
    tag_name = match.group(1).replace("-", ".").replace("::", ".")
    view_name = f"components.{tag_name}"
    attrs = match.group(2) or ""
    array_str = _parse_component_attrs(attrs)
    code = f"<?php view('{view_name}'{array_str}); ?>"
    return _keep_lines(code, match.group(0))


def to_php(text: str) -> str:
    """Rewrite Blade into PHP the tree-sitter php grammar can read."""
    literals: list[str] = []

    def _stash(match: re.Match[str]) -> str:
        literals.append(match.group(0))
        return _LITERAL_PLACEHOLDER

    text = _LITERAL.sub(_stash, text)
    text = _COMMENT.sub(lambda m: _keep_lines("", m.group(0)), text)

    def _rewrite_script_block(match: re.Match[str]) -> str:
        block = match.group(0)
        block = _RAW_ECHO.sub(
            lambda m: _keep_lines(f"<?php vigilloo_js_sink({m.group(1)}); ?>", m.group(0)), block
        )
        block = _ESCAPED_ECHO.sub(
            lambda m: _keep_lines(f"<?php vigilloo_js_sink(e({m.group(1)})); ?>", m.group(0)), block
        )
        return block

    text = _SCRIPT_BLOCK.sub(_rewrite_script_block, text)

    text = _PHP_BLOCK.sub(lambda m: _keep_lines(f"<?php {m.group(1)}?>", m.group(0)), text)
    text = _RAW_ECHO.sub(lambda m: _keep_lines(f"<?php echo {m.group(1)}; ?>", m.group(0)), text)
    text = _ESCAPED_ECHO.sub(lambda m: _keep_lines(f"<?php e({m.group(1)}); ?>", m.group(0)), text)
    text = _INCLUDE.sub(lambda m: _keep_lines(f"<?php view({m.group(1)}); ?>", m.group(0)), text)
    text = _EXTENDS.sub(lambda m: _keep_lines(f"<?php view({m.group(1)}); ?>", m.group(0)), text)
    text = _COMPONENT_DIRECTIVE.sub(
        lambda m: _keep_lines(f"<?php view({m.group(1)}); ?>", m.group(0)), text
    )
    text = _COMPONENT_TAG.sub(_rewrite_component_tag, text)

    text = _FOREACH.sub(lambda m: _keep_lines(f"<?php foreach({m.group(1)}): ?>", m.group(0)), text)
    text = _ENDFOREACH.sub(lambda m: _keep_lines("<?php endforeach; ?>", m.group(0)), text)
    text = _FORELSE.sub(lambda m: _keep_lines(f"<?php foreach({m.group(1)}): ?>", m.group(0)), text)
    text = _EMPTY.sub(lambda m: _keep_lines("<?php endforeach; ?>", m.group(0)), text)
    text = _ENDFORELSE.sub(lambda m: _keep_lines("<?php ; ?>", m.group(0)), text)
    text = _FOR.sub(lambda m: _keep_lines(f"<?php for({m.group(1)}): ?>", m.group(0)), text)
    text = _ENDFOR.sub(lambda m: _keep_lines("<?php endfor; ?>", m.group(0)), text)
    text = _WHILE.sub(lambda m: _keep_lines(f"<?php while({m.group(1)}): ?>", m.group(0)), text)
    text = _ENDWHILE.sub(lambda m: _keep_lines("<?php endwhile; ?>", m.group(0)), text)

    for literal in literals:
        text = text.replace(_LITERAL_PLACEHOLDER, literal, 1)
    return text
