module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testTimeout: 45000,
  watchman: false,
  testMatch: ['**/tests/**/*.test.ts'],
  transform: {
    '^.+\\.tsx?$': 'ts-jest'
  }
};
