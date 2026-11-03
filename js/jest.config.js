/**
 * For a detailed explanation regarding each configuration property, visit:
 * https://jestjs.io/docs/configuration
 */

/** @type {import('ts-jest').JestConfigWithTsJest} */
const base = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  setupFiles: ['<rootDir>/jest-setup.js'],
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      tsconfig: 'tsconfig.json',
    }],
  },
};

/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  projects: [
    {
      ...base,
      displayName: 'unit',
      roots: ['<rootDir>/src', '<rootDir>/__tests__'],
      testPathIgnorePatterns: ['/node_modules/', '<rootDir>/__tests__/wasm/'],
    },
    {
      ...base,
      displayName: 'wasm',
      roots: ['<rootDir>/__tests__/wasm'],
    },
  ],
};
