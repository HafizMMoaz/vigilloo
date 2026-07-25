from vigilloo.laravel.vocabulary import is_source, sink_arg_index


def test_request_input_is_a_source() -> None:
    assert is_source("input")
    assert is_source("query")
    assert is_source("all")
    assert not is_source("validated")


def test_raw_sinks_declare_the_dangerous_argument() -> None:
    """whereRaw('age > ?', [$age]) is safe; only argument 0 is a sink."""
    assert sink_arg_index("orderByRaw") == 0
    assert sink_arg_index("whereRaw") == 0
    assert sink_arg_index("orderBy") is None
    assert sink_arg_index("where") is None
