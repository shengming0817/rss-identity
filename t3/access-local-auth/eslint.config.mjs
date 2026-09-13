export default [{
  files: ['*.mjs'],
  languageOptions: {
    ecmaVersion: 'latest', sourceType: 'module',
    globals: Object.fromEntries(['Buffer', 'URL', 'Headers', 'Response', 'process', 'console',
      'setTimeout', 'setInterval', 'clearInterval', 'localStorage', 'sessionStorage'].map(name => [name, 'readonly'])),
  },
  rules: { 'no-undef': ['error', { typeof: true }] },
}]
