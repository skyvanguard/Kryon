"""T4-M5: SAST now covers Java/Go/Ruby (and PHP unserialize), not just py/js/php."""

from __future__ import annotations

import os

os.environ["OPENAI_API_KEY"] = "test_key_for_ci_environment"

from kryon.intelligence.sast_rules import scan_text


def _rules(text: str, filename: str) -> set[str]:
    return {f.rule_id for f in scan_text(text, filename)}


def test_java_cmdi_and_deser():
    code = "Runtime.getRuntime().exec(userInput);\nObjectInputStream o = new ObjectInputStream(in);\no.readObject();"
    hits = _rules(code, "App.java")
    assert "sast-java-cmdi" in hits
    assert "sast-java-deser" in hits


def test_java_xxe():
    assert "sast-java-xxe" in _rules("DocumentBuilderFactory.newInstance();", "Parse.java")


def test_go_cmdi_and_sqli():
    code = 'exec.Command("/bin/sh", "-c", x)\ndb.Query(fmt.Sprintf("select * from t where id=%s", id))'
    hits = _rules(code, "main.go")
    assert "sast-go-cmdi" in hits
    assert "sast-go-sqli" in hits


def test_ruby_cmdi_and_eval():
    code = 'system("ping #{params[:host]}")\neval(params[:code])'
    hits = _rules(code, "app.rb")
    assert "sast-ruby-cmdi" in hits
    assert "sast-ruby-eval" in hits


def test_ruby_comment_is_not_flagged():
    assert "sast-ruby-cmdi" not in _rules('# system("ping #{x}")', "app.rb")


def test_php_unserialize_user_input():
    assert "sast-php-deser" in _rules("$o = unserialize($_GET['data']);", "x.php")


def test_language_isolation():
    # A Go sink pattern in a .py file must not fire Go rules.
    assert "sast-go-cmdi" not in _rules('exec.Command("/bin/sh")', "x.py")
