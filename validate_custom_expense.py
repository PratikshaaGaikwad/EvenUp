from pathlib import Path
import py_compile
import re
import subprocess
from app import app

for name in ('app.py', 'db.py'):
    py_compile.compile(name, doraise=True)

for template in sorted(Path('templates').glob('*.html')):
    app.jinja_env.get_template(template.name)

source = Path('templates/group_detail.html').read_text(encoding='utf-8')
assert 'value="custom">Custom receipt / itemized split' in source
assert 'name="items_json"' in source
assert 'name="receipt_file"' in source
assert 'expense.category == option' in source
assert 'member.id == current_user.id' in source
assert 'member.id="' not in source
assert 'expense.category="' not in source

scripts = re.findall(r'<script>(.*?)</script>', source, re.S)
javascript = '\n'.join(scripts)
javascript = re.sub(r'{%.*?%}', '', javascript, flags=re.S)
javascript = re.sub(r'{{.*?}}', 'null', javascript, flags=re.S)
Path('/tmp/evenup_group_detail.js').write_text(javascript, encoding='utf-8')
subprocess.run(['node', '--check', '/tmp/evenup_group_detail.js'], check=True)
print('OK Python compilation')
print('OK all Jinja templates compile')
print('OK custom itemizer and receipt controls present')
print('OK group detail JavaScript syntax')
