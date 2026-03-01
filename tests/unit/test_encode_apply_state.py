import gzip
import json
import pytest
from base64 import b64decode

# The module under test has no Flask dependencies, so import it directly.
from powerdnsadmin.lib.dc_utils import encode_apply_state, decode_apply_state


TEMPLATE = {
    "providerId": "exampleProvider",
    "serviceId": "exampleService",
    "records": [{"type": "A", "host": "@", "pointsTo": "1.2.3.4", "ttl": 3600}],
}

APPLY_RESULT = [
    [],                                          # deleted records
    [],                                          # unchanged records
    [{"type": "A", "host": "@", "pointsTo": "1.2.3.4", "ttl": 3600}],  # added records
]


def _roundtrip(**kwargs):
    token = encode_apply_state(**kwargs)
    return decode_apply_state(token)


def _base_kwargs(**overrides):
    base = dict(
        template=TEMPLATE,
        zone_records=[],
        domain="example.com",
        host="www",
        group_ids=["g1", "g2"],
        params={"ip": ["1.2.3.4"], "host": ["www"]},
        ignore_signature=True,
        multi_aware=True,
        dc_apply_result=APPLY_RESULT,
    )
    base.update(overrides)
    return base


class TestEncodeApplyState:
    def test_returns_string(self):
        token = encode_apply_state(**_base_kwargs())
        assert isinstance(token, str)

    def test_token_is_valid_base64(self):
        token = encode_apply_state(**_base_kwargs())
        # Should not raise
        b64decode(token)

    def test_token_compresses_with_gzip(self):
        token = encode_apply_state(**_base_kwargs())
        compressed = b64decode(token)
        # Should not raise
        raw = gzip.decompress(compressed)
        payload = json.loads(raw)
        assert "template" in payload

    def test_identical_inputs_produce_identical_tokens(self):
        kwargs = _base_kwargs()
        assert encode_apply_state(**kwargs) == encode_apply_state(**kwargs)


class TestDecodeApplyState:
    def test_roundtrip_template(self):
        payload = _roundtrip(**_base_kwargs())
        assert payload["template"] == TEMPLATE

    def test_roundtrip_domain(self):
        payload = _roundtrip(**_base_kwargs())
        assert payload["domain"] == "example.com"

    def test_roundtrip_host(self):
        payload = _roundtrip(**_base_kwargs())
        assert payload["host"] == "www"

    def test_roundtrip_zone_records(self):
        payload = _roundtrip(**_base_kwargs())
        assert payload["zone_records"] == []

    def test_roundtrip_group_ids(self):
        payload = _roundtrip(**_base_kwargs())
        assert payload["group_ids"] == ["g1", "g2"]

    def test_roundtrip_params_plain_dict(self):
        payload = _roundtrip(**_base_kwargs())
        assert payload["params"] == {"ip": ["1.2.3.4"], "host": ["www"]}

    def test_params_underscore_keys_preserved(self):
        """encode_apply_state does not filter keys — filtering is the caller's job."""
        params_with_internal = {"ip": ["1.2.3.4"], "_csrf_token": ["tok"], "_template": ["t"]}
        payload = _roundtrip(**_base_kwargs(params=params_with_internal))
        assert "_csrf_token" in payload["params"]
        assert "_template" in payload["params"]

    def test_roundtrip_ignore_signature(self):
        payload = _roundtrip(**_base_kwargs())
        assert payload["ignore_signature"] is True

    def test_roundtrip_multi_aware(self):
        payload = _roundtrip(**_base_kwargs())
        assert payload["multi_aware"] is True

    def test_roundtrip_dc_apply_result(self):
        payload = _roundtrip(**_base_kwargs())
        assert payload["dc_apply_result"] == APPLY_RESULT

    def test_roundtrip_werkzeug_multidict(self):
        """params coming from a Werkzeug ImmutableMultiDict are serialised correctly."""
        try:
            from werkzeug.datastructures import ImmutableMultiDict
            params = ImmutableMultiDict([("ip", "1.2.3.4"), ("host", "www")])
        except ImportError:
            pytest.skip("werkzeug not available")
        payload = _roundtrip(**_base_kwargs(params=params))
        # to_dict(flat=False) gives lists
        assert payload["params"]["ip"] == ["1.2.3.4"]
        assert payload["params"]["host"] == ["www"]

    def test_empty_group_ids(self):
        payload = _roundtrip(**_base_kwargs(group_ids=[]))
        assert payload["group_ids"] == []

    def test_empty_apply_result(self):
        payload = _roundtrip(**_base_kwargs(dc_apply_result=[[], [], []]))
        assert payload["dc_apply_result"] == [[], [], []]

    def test_unicode_in_domain(self):
        payload = _roundtrip(**_base_kwargs(domain="münchen.example.com"))
        assert payload["domain"] == "münchen.example.com"

    def test_large_template(self):
        large_records = [{"type": "A", "host": f"host{i}", "pointsTo": "1.2.3.4", "ttl": 60}
                         for i in range(500)]
        large_template = {**TEMPLATE, "records": large_records}
        payload = _roundtrip(**_base_kwargs(template=large_template))
        assert len(payload["template"]["records"]) == 500

    def test_invalid_token_raises(self):
        with pytest.raises(Exception):
            decode_apply_state("not-valid-base64!!!")

    def test_corrupted_token_raises(self):
        token = encode_apply_state(**_base_kwargs())
        # Flip a few bytes after decoding to corrupt the gzip stream
        data = bytearray(b64decode(token))
        data[10] ^= 0xFF
        from base64 import b64encode
        bad_token = b64encode(bytes(data)).decode("ascii")
        with pytest.raises(Exception):
            decode_apply_state(bad_token)
