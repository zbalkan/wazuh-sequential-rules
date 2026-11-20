# Wazuh sequential rule demo

Demo rules, decoder and tests for [Understanding Wazuh rules, part III: sequential correlation](https://zaferbalkan.com/wazuh-rules-sequential/). Rule C (`100575`) fires when rule B (`100505`) matches an event and rule A (`100570`) matched an earlier event from the same source IP within 60 seconds.

## Layout

- `rules/sequential_rules.xml`: rules A, B and C
- `decoders/sequential_decoder.xml`: the `seqdemo` decoder used by the test events
- `tests/regression_tests/test_sequential_rules.py`: logtest scenarios for the sequence

## Running the tests

The tests run in a [wazuhdevenv](https://github.com/zbalkan/wazuhdevenv) workspace against a Wazuh v4.14.10 manager, through [wazuhtester](https://github.com/zbalkan/wazuhtester).

1. Copy `rules/`, `decoders/` and `tests/` into the workspace.
2. Check that the ruleset loads: `sudo /var/ossec/bin/wazuh-analysisd -t`
3. Run the fast tests: `python -m pytest tests -m "not slow"`
4. Run the full suite, including the 60-second window test: `python -m pytest tests`

## Licence

See [LICENSE](LICENSE).
