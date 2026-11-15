import unittest

from hookguard.diff import file_as_change, parse_unified_diff
from hookguard.rules import RuleEngine

DIFF = """\
diff --git a/app.py b/app.py
index 111..222 100644
--- a/app.py
+++ b/app.py
@@ -1,4 +1,5 @@
 import os
-x = 1
+x = 2
+y = eval(user_input)
 def f():
     pass
@@ -20,2 +21,3 @@ def g():
     a = 1
+    os.system("rm -rf " + path)
     return a
diff --git a/new.js b/new.js
new file mode 100644
index 000..333
--- /dev/null
+++ b/new.js
@@ -0,0 +1,2 @@
+el.innerHTML = userHtml;
+console.log("ok");
diff --git a/logo.png b/logo.png
new file mode 100644
Binary files /dev/null and b/logo.png differ
"""


class DiffTests(unittest.TestCase):
    def test_parse_line_numbers(self):
        files = parse_unified_diff(DIFF)
        self.assertEqual([f.path for f in files], ["app.py", "new.js"])
        app = files[0]
        self.assertEqual([(a.lineno, a.text) for a in app.added],
                         [(2, "x = 2"), (3, "y = eval(user_input)"), (22, '    os.system("rm -rf " + path)')])
        self.assertTrue(files[1].is_new_file)
        self.assertEqual(files[1].added[0].lineno, 1)

    def test_file_as_change(self):
        ch = file_as_change("a.py", "one\ntwo\n")
        self.assertEqual([a.lineno for a in ch.added], [1, 2])


class RuleTests(unittest.TestCase):
    def test_rules_on_diff(self):
        files = parse_unified_diff(DIFF)
        eng = RuleEngine()
        py = {(f.rule, f.line) for f in eng.scan(files[0])}
        self.assertEqual(py, {("py-eval-exec", 3), ("py-os-system", 22)})
        js = {f.rule for f in eng.scan(files[1])}
        self.assertEqual(js, {"js-inner-html"})

    def test_false_positive_guards(self):
        eng = RuleEngine()
        code = "\n".join([
            "model.eval()",
            "ast.literal_eval(s)",
            "data = yaml.load(f, Loader=yaml.SafeLoader)",
            "# eval(x) in a comment",
            "cur.execute('SELECT * FROM t WHERE id = %s', (i,))",
        ])
        self.assertEqual(eng.scan(file_as_change("ok.py", code)), [])

    def test_rule_applies_by_extension(self):
        eng = RuleEngine()
        self.assertEqual(eng.scan(file_as_change("README.md", "eval(x)")), [])

    def test_disable_rule(self):
        eng = RuleEngine(disabled=["py-eval-exec"])
        self.assertEqual(eng.scan(file_as_change("a.py", "eval(x)")), [])


if __name__ == "__main__":
    unittest.main()
