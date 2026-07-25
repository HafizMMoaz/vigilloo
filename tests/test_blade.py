from vigilloo.laravel.blade import to_php


def test_escaped_echo_becomes_an_e_call() -> None:
    """{{ }} compiles to e() in Laravel, so auto-escaping needs no special case."""
    assert to_php("{{ $x }}") == "<?php e( $x ); ?>"


def test_raw_echo_becomes_a_bare_echo() -> None:
    assert to_php("{!! $x !!}") == "<?php echo  $x ; ?>"


def test_comments_are_stripped() -> None:
    assert to_php("{{-- $secret --}}").strip() == ""


def test_literal_braces_are_left_alone() -> None:
    """@{{ x }} is for JS frameworks and must not become PHP."""
    assert "e(" not in to_php("@{{ x }}")


def test_php_blocks_are_inlined() -> None:
    assert to_php("@php $a = 1; @endphp") == "<?php  $a = 1; ?>"


def test_line_numbers_are_preserved() -> None:
    """The whole design rests on this: no span mapping table to drift."""
    template = "\n".join(
        [
            "<div>",
            "  {{-- a comment --}}",
            "  {!! $raw !!}",
            "  <p>text</p>",
            "  {{ $safe }}",
            "</div>",
        ]
    )
    out = to_php(template).splitlines()

    assert len(out) == 6
    assert "echo" in out[2]
    assert "e(" in out[4]


def test_multiline_construct_preserves_the_line_count() -> None:
    template = "a\n{{--\nlong\ncomment\n--}}\nb"
    assert len(to_php(template).splitlines()) == 6


def test_surrounding_markup_is_left_as_inert_text() -> None:
    """The text-mode grammar treats non-PHP as inert, so blanking it is wasted work."""
    assert "<div>" in to_php("<div>{{ $x }}</div>")
