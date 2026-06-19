"""Deterministic SAST ruleset — per-language sink detection + FP guards."""

from __future__ import annotations

from kryon.intelligence.sast_rules import scan_path, scan_text, to_findings


def _rules(text, fn):
    return {f.rule_id for f in scan_text(text, fn)}


def test_python_sqli_fstring():
    assert "sast-py-sqli" in _rules('cursor.execute(f"SELECT * FROM u WHERE id={uid}")', "a.py")


def test_python_sqli_concat():
    assert "sast-py-sqli" in _rules('cur.execute("SELECT * FROM u WHERE n=" + name)', "a.py")


def test_python_cmdi_shell_true():
    assert "sast-py-cmdi" in _rules("subprocess.run(cmd, shell=True)", "a.py")
    assert "sast-py-cmdi" in _rules("os.system('ping ' + host)", "a.py")


def test_python_cmdi_comment_guarded():
    assert "sast-py-cmdi" not in _rules("# os.system is dangerous", "a.py")


def test_python_deser():
    assert "sast-py-deser" in _rules("data = pickle.loads(blob)", "a.py")
    assert "sast-py-deser" in _rules("cfg = yaml.load(f)", "a.py")


def test_python_weak_crypto():
    assert "sast-py-weakcrypto" in _rules("h = hashlib.md5(pw).hexdigest()", "a.py")


def test_python_eval():
    assert "sast-py-eval" in _rules("result = eval(user_input)", "a.py")
    assert "sast-py-eval" not in _rules("result = eval('1+1')", "a.py")  # literal
    assert "sast-py-eval" not in _rules("x = ast.literal_eval(s)", "a.py")  # safe


def test_hardcoded_secret_and_env_guard():
    assert "sast-hardcoded-secret" in _rules('password = "Sup3rSecret!"', "a.py")
    assert "sast-hardcoded-secret" not in _rules('password = os.environ["PW"]', "a.py")
    assert "sast-hardcoded-secret" not in _rules('password = "changeme"', "a.py")


def test_python_ssrf():
    assert "sast-py-ssrf" in _rules("requests.get(request.args['url'])", "a.py")


def test_js_dom_xss():
    assert "sast-js-domxss" in _rules("el.innerHTML = userInput;", "a.js")
    assert "sast-js-domxss" in _rules("<div dangerouslySetInnerHTML={{__html: x}} />", "a.jsx")


def test_js_eval_comment_guard():
    assert "sast-js-eval" in _rules("eval(payload)", "a.ts")
    assert "sast-js-eval" not in _rules("// eval is bad", "a.ts")


def test_php_cmdi_and_lfi():
    assert "sast-php-cmdi" in _rules("system($_GET['cmd']);", "a.php")
    assert "sast-php-lfi" in _rules("include($_GET['page']);", "a.php")
    assert "sast-php-sqli" in _rules("mysqli_query($c, $_POST['q']);", "a.php")


def test_extension_scoping():
    # a .py rule shouldn't fire on a .js file and vice versa.
    assert scan_text("pickle.loads(x)", "a.js") == []


def test_no_fp_on_clean_code():
    assert scan_text("def add(a, b):\n    return a + b\n", "a.py") == []


def test_scan_path(tmp_path):
    (tmp_path / "v.py").write_text('cursor.execute("SELECT * FROM t WHERE x=" + v)\n')
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "skip.py").write_text("eval(x)\n")
    findings = scan_path(str(tmp_path))
    files = {f.file for f in findings}
    assert any("v.py" in f for f in files)
    assert not any("node_modules" in f for f in files)  # skip dir honored


def test_to_findings_needs_verification(tmp_path):
    sast = scan_text('cursor.execute(f"SELECT {x}")', "a.py")
    findings = to_findings(sast, "local")
    assert findings and findings[0].needs_verification is True and findings[0].cwe == "CWE-89"
    assert findings[0].confidence < 1.0
