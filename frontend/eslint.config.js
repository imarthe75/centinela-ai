import js from '@eslint/js'
import globals from 'globals'
import react from 'eslint-plugin-react'
import reactHooks from 'eslint-plugin-react-hooks'

// ADR-0008 #2: the rules that catch the real risks of moving code between files (undefined names, wrong hook usage).
export default [
  { ignores: ['dist', 'node_modules'] },
  {
    files: ['**/*.{js,jsx}'],
    languageOptions: { ecmaVersion: 2023, sourceType: 'module', globals: { ...globals.browser }, parserOptions: { ecmaFeatures: { jsx: true } } },
    plugins: { react, 'react-hooks': reactHooks },
    settings: { react: { version: '19' } },
    rules: {
      'no-undef': 'error',
      'react/jsx-no-undef': 'error',
      'react-hooks/rules-of-hooks': 'error',
      'no-unused-vars': ['warn', { varsIgnorePattern: '^_', args: 'none', ignoreRestSiblings: true }],
      'react/jsx-uses-vars': 'error',
      'react/jsx-uses-react': 'off',
    },
  },
  // build/test config runs in Node, not the browser
  { files: ['vite.config.js', 'vitest.config.js'], languageOptions: { globals: { ...globals.node } } },
]
