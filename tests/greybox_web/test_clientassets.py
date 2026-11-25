from src.greybox_web.tools.clientassets import classify


def test_source_map_requires_non_public_original_source_detail():
    assert classify("http://app/main.js.map", '{"sourcesContent":["const API=\\"https://admin.internal:8443\\"; // feature flag"]}')[0] == "source_map"
    assert classify("http://app/main.js.map", '{"sourcesContent":["console.log(1)"]}') == (None, None)


def test_runtime_configuration_distinguishes_admin_and_public_keys():
    text = '{"publicKey":"lmn_pub_pk_123456789","search":{"adminKey":"lmn_live_sk_123456789"}}'
    assert classify("http://app/config.json", text) == ("secret_config", "search.adminKey")
    assert classify("http://app/config.json", '{"publicKey":"lmn_pub_pk_123456789"}') == (None, None)
