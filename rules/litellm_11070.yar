// SPDX-License-Identifier: MIT
// Independently authored from the public analyses cited below.
// Content matches are investigation leads, not proof of execution.

rule LiteLLM_11070_EncodedCollector : python supply_chain hunting
{
    meta:
        description = "Known compressed collector fingerprint with Python decoding/execution markers"
        author = "Contributors"
        date = "2026-10-22"
        version = "1"
        license = "MIT"
        reference = "https://research.jfrog.com/post/litellm-hijacked-again/"
        sample_sha256 = "9dd0a3926f96a37eb86cf1ee2310d9be93139cc4ebef3ef9e2efe9531390be25"
        scope = "Raw cook.py and the embedded collector in sitecustomize.py; not arbitrary repacked variants"
    strings:
        $blob = "eNrdfWt327qu4Pf+Ck/XdCTvxu9HnJydcydN0zZtHt1J+nRytGSJtlXLkirJdpKuzm8" ascii
        $decode = "b64decode" ascii
        $decompress = "decompress" ascii
        $execute = /exec[ \t\r\n]*\(/
    condition:
        filesize < 2MB and all of them
}

rule LiteLLM_11070_RemoteLoader : python supply_chain backdoor
{
    meta:
        description = "Campaign anchor plus remote execution and detached-loader structure"
        author = "Contributors"
        date = "2026-10-22"
        version = "1"
        license = "MIT"
        reference = "https://research.jfrog.com/post/litellm-hijacked-again/"
        sample_sha256 = "34bef04fe88ac9d0aae0475630b1738681d15b94f233ac8aa46eacf5968305fa"
        scope = "Loader source or bytecode retaining the selected strings; not downloaded second stages"
    strings:
        $anchor_lock = "remote_code_loader.lock" ascii
        $anchor_repository = "letters9813/pythonclient-test" ascii
        $endpoint = "/codepy" ascii
        $remote_code = "<remote>" ascii
        $structure_lock = "_acquire_daemon_lock" ascii
        $structure_detach = "_daemonize" ascii
        $structure_loop = "_run_forever" ascii
        $structure_locator = "GITHUB_RAW_URL" ascii
    condition:
        filesize < 2MB and
        any of ($anchor_*) and $endpoint and $remote_code and
        3 of ($structure_*)
}

rule LiteLLM_11070_DecodedCollector : python supply_chain credential_theft
{
    meta:
        description = "Plaintext privcollect collector with crypto/transport and credential-collection structure"
        author = "Contributors"
        date = "2026-10-22"
        version = "1"
        license = "MIT"
        reference = "https://opensourcemalware.com/blog/litellm-1-107-0-pypi-wheel-contains-a-credential-stealer-and-persistent-python-backdoor"
        decoded_sample_sha256 = "6ea3d8ef6cf73a72d8df24f663b7a31ce67494eeb9b0d707b93484e66675d2df"
        scope = "Statically decoded source or bytecode; this rule does not itself decode base64/zlib"
    strings:
        $guard = "PRIVCOLLECT_ACTIVE" ascii
        $label = "privcollect" ascii
        $crypto_aes = "pc_aes_enc" ascii
        $crypto_rsa = "pc_rsa_enc" ascii
        $crypto_transport = "pc_post" ascii
        $crypto_envelope = "pc_pack" ascii
        $collect_environment = "mod_env_vars" ascii
        $collect_ssh = "mod_ssh_keys" ascii
        $collect_ai = "mod_ai_devtools" ascii
        $collect_database = "mod_db_litellm" ascii
        $collect_cloud = "mod_cloud_metadata" ascii
    condition:
        filesize < 2MB and $guard and $label and
        3 of ($crypto_*) and 3 of ($collect_*)
}
