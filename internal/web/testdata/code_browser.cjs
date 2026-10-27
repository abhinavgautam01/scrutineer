const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const script = fs.readFileSync('static/code_browser.js', 'utf8');
const pages = JSON.parse(fs.readFileSync(0, 'utf8'));
for (const page of pages) {
  const bounds = page.HTML.match(/data-hl-from="(\d+)" data-hl-to="(\d+)"/);
  const content = page.HTML.match(/<code id="blob"[^>]*>([\s\S]*?)<\/code>/);
  assert.ok(bounds && content, 'rendered code and highlight bounds');
  const highlighted = [];
  const scrolled = [];
  let lookups = 0;
  const code = {
    innerHTML: content[1],
    parentElement: {parentElement: {getAttribute: name => bounds[name === 'data-hl-from' ? 1 : 2]}}
  };
  const lineCount = content[1].split('\n').length;
  const document = {getElementById: id => {
    if (id === 'blob') return code;
    lookups++;
    const line = Number(id.slice(1));
    if (line < 1 || line > lineCount) return null;
    return {classList: {add: name => {assert.equal(name, 'hl-on'); highlighted.push(line);}},
      scrollIntoView: () => scrolled.push(line)};
  }};
  vm.runInNewContext(script, {document, window: {}}, {timeout: 1000});
  assert.deepEqual(highlighted, page.Highlighted, page.Query);
  assert.deepEqual(scrolled, page.Scrolled, page.Query);
  assert.ok(lookups <= lineCount + 1, 'lookups bounded by rendered lines');
}
