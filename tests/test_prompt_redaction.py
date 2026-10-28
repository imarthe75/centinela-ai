from core.prompt_redaction import REDACTED, redact_secrets


def red(t):
    return redact_secrets(t)[0]


def test_property_and_yaml_secret_values_are_removed():
    t = "spring.datasource.password=Sup3rS3cret!\nkeycloak.credentials.secret: abcd1234efgh\n"
    out, n = redact_secrets(t)
    assert "Sup3rS3cret" not in out and "abcd1234efgh" not in out and n == 2
    assert "spring.datasource.password=" in out and "keycloak.credentials.secret:" in out   # the KEY stays: the analysis still knows what it is


def test_json_and_code_assignments():
    assert "hunter2hunter2" not in red('{"apiKey": "hunter2hunter2"}')
    assert "tok_live_123456" not in red("const token = 'tok_live_123456';")
    assert "x9y8z7w6" not in red('String password = "x9y8z7w6";')


def test_references_placeholders_and_non_secrets_are_kept():
    for keep in ["password=${DB_PASSWORD}", "secret: <your-secret>", "token = process.env.TOKEN", "password=changeme",
                 "requirePasswordChange=true", "tokenizer.encode(text)", "passwordPolicy: strong", "let author = getAuthor();"]:
        assert red(keep) == keep, keep


def test_token_shapes():
    for secret in ["AKIAIOSFODNN7EXAMPLE", "glpat-abcdefghijklmnopqrst", "ghp_" + "a" * 36,
                   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r",
                   "$2a$10$" + "N9qo8uLOickgx2ZMRZoMye" + "IjZAgcfl7p92ldGxad68LJZdL17lhWy"]:
        assert secret not in red("x " + secret + " y"), secret


def test_private_key_block_and_url_credentials():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\nabc\n-----END RSA PRIVATE KEY-----"
    assert "MIIEow" not in red("k:\n" + pem)
    out = red("jdbc:postgresql://u:p4ssw0rd@192.0.2.13/db and https://admin:s3cr3t@host/x")
    assert "p4ssw0rd" not in out and "s3cr3t" not in out and "192.0.2.13/db" in out


def test_empty_and_clean_text_are_untouched():
    assert redact_secrets("") == ("", 0)
    clean = "public void guardar(UsuarioDto dto) { repo.save(dto.toEntity()); }"
    assert redact_secrets(clean) == (clean, 0)
