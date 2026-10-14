from pathlib import Path
import py_compile
from app import app

for path in Path('.').glob('*.py'):
    if path.name != Path(__file__).name:
        py_compile.compile(str(path), doraise=True)

for template in sorted(Path('templates').glob('*.html')):
    app.jinja_env.get_template(template.name)
    print(f'OK template {template.name}')

bad_patterns = ['group.group_type="', 'expense.category="', 'member.id="']
for template in Path('templates').glob('*.html'):
    text = template.read_text(encoding='utf-8')
    for pattern in bad_patterns:
        if pattern in text:
            raise SystemExit(f'Invalid pattern {pattern} in {template}')

print('OK Python compilation')
print('OK invalid assignment patterns absent')
