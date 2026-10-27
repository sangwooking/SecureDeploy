const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const ts = require('typescript');
const React = require('react');
const { renderToStaticMarkup } = require('react-dom/server');

const source = fs.readFileSync(path.join(__dirname, '../src/App.tsx'), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

function load(react = React) {
  const exports = {};
  new Function('require', 'exports', compiled)(specifier => {
    if (specifier === 'react') return react;
    if (specifier.startsWith('./')) return {};
    return require(specifier);
  }, exports);
  return exports.AuthScreen;
}

const defaults = {
  mode: 'LOGIN', email: '', password: '', name: '', errorMessage: '', isLoading: false,
  onModeChange() {}, onEmailChange() {}, onPasswordChange() {}, onNameChange() {}, onSubmit() {},
};
const render = props => renderToStaticMarkup(React.createElement(load(), { ...defaults, ...props }));
const inputs = html => [...html.matchAll(/<input\b[^>]*>/g)].map(match => match[0]);

// Keep event tests offline with a small hook harness; markup assertions use real React SSR.
function harness(overrides = {}) {
  const state = [], dependencies = [];
  let cursor = 0, effects = [];
  const Screen = load({ ...React,
    useState(initial) {
      const index = cursor++;
      if (!(index in state)) state[index] = initial;
      return [state[index], value => { state[index] = typeof value === 'function' ? value(state[index]) : value; }];
    },
    useEffect(effect, deps) {
      const index = cursor++;
      if (!dependencies[index] || deps.some((value, i) => value !== dependencies[index][i])) {
        dependencies[index] = deps;
        effects.push(effect);
      }
    },
  });
  const props = { ...defaults, ...overrides };
  return { props, render() {
    cursor = 0;
    const tree = Screen(props);
    effects.forEach(effect => effect());
    effects = [];
    return tree;
  } };
}

function find(tree, predicate) {
  if (!tree || typeof tree !== 'object') return undefined;
  if (predicate(tree)) return tree;
  for (const child of React.Children.toArray(tree.props?.children)) {
    const found = find(child, predicate);
    if (found) return found;
  }
}
const field = (tree, name) => find(tree, node => node.type === 'input' && node.props.name === name);

test('auth modes retain labels, native constraints and password-manager semantics', () => {
  const login = render({}), signup = render({ mode: 'SIGNUP' });
  assert.ok(login.includes('SecureDeploy'));
  assert.ok(login.includes('배포 전 검토'));
  assert.equal(inputs(login).length, 2);
  assert.equal(inputs(signup).length, 3);
  assert.ok(login.includes('autoComplete="current-password"'));
  assert.ok(signup.includes('autoComplete="new-password"'));
  for (const html of [login, signup]) {
    assert.ok(html.includes('minLength="8"'));
    assert.ok(inputs(html).every(input => input.includes('required=""')));
    assert.ok(!html.includes('aria-invalid='));
    assert.ok(html.includes('aria-label="비밀번호 표시"'));
    assert.ok(html.includes('aria-controls="auth-password"'));
  }
});

test('authentication errors are escaped, announced and described without blaming valid fields', () => {
  const html = render({ errorMessage: '<server unavailable>' });
  assert.ok(html.includes('id="auth-error" role="alert"'));
  assert.ok(html.includes('&lt;server unavailable&gt;'));
  assert.ok(!html.includes('<server unavailable>'));
  assert.ok(!html.includes('aria-invalid='));
  assert.ok(inputs(html).every(input => /aria-describedby="[^"]*auth-error/.test(input)));
  assert.ok(!render({}).includes('auth-error'));
});

test('submitting keeps every input and button disabled and exposes busy state', () => {
  const html = render({ mode: 'SIGNUP', isLoading: true });
  assert.ok(html.includes('aria-busy="true"'));
  assert.ok(html.includes('처리 중...'));
  const controls = [...html.matchAll(/<(?:input|button)\b[^>]*>/g)];
  assert.ok(controls.every(([tag]) => tag.includes('disabled=""')));
});

test('password visibility toggles without changing its value or submitting and resets across modes', () => {
  const view = harness({ password: 'test-password' });
  let tree = view.render();
  const toggle = () => find(tree, node => node.props?.['aria-controls'] === 'auth-password');
  assert.equal(field(tree, 'password').props.type, 'password');
  assert.equal(toggle().props.type, 'button');
  toggle().props.onClick();
  tree = view.render();
  assert.equal(field(tree, 'password').props.type, 'text');
  assert.equal(field(tree, 'password').props.value, 'test-password');
  assert.equal(toggle().props['aria-label'], '비밀번호 숨기기');
  assert.equal(toggle().props['aria-pressed'], true);
  toggle().props.onClick();
  tree = view.render();
  assert.equal(field(tree, 'password').props.type, 'password');
  toggle().props.onClick();
  view.props.mode = 'SIGNUP';
  view.render();
  tree = view.render();
  assert.equal(field(tree, 'password').props.type, 'password');
});

test('only native invalid fields receive invalid semantics and valid edits clear them', () => {
  const view = harness();
  let tree = view.render();
  const form = find(tree, node => node.type === 'form');
  form.props.onInvalid({ target: { name: 'email' } });
  tree = view.render();
  assert.equal(field(tree, 'email').props['aria-invalid'], true);
  assert.equal(field(tree, 'password').props['aria-invalid'], undefined);
  form.props.onInput({ target: { name: 'email', validity: { valid: false } } });
  assert.equal(field(view.render(), 'email').props['aria-invalid'], true);
  form.props.onInput({ target: { name: 'email', validity: { valid: true } } });
  assert.equal(field(view.render(), 'email').props['aria-invalid'], undefined);
  form.props.onInvalid({ target: { name: 'email' } });
  view.props.mode = 'SIGNUP';
  view.render();
  assert.equal(field(view.render(), 'email').props['aria-invalid'], undefined);
});

test('form and field callbacks preserve submitted events and unmodified input values', () => {
  const calls = [];
  const view = harness({ mode: 'SIGNUP',
    onSubmit: event => calls.push(event),
    onEmailChange: value => calls.push(value),
    onPasswordChange: value => calls.push(value),
    onNameChange: value => calls.push(value),
    onModeChange: value => calls.push(value),
  });
  const tree = view.render(), event = {};
  find(tree, node => node.type === 'form').props.onSubmit(event);
  for (const name of ['email', 'password', 'name']) field(tree, name).props.onChange({ target: { value: ' unchanged ' } });
  find(tree, node => node.type === 'button' && node.props.children === '로그인').props.onClick();
  assert.deepEqual(calls, [event, ' unchanged ', ' unchanged ', ' unchanged ', 'LOGIN']);
});
