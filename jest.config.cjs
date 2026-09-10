module.exports = {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "node",
  extensionsToTreatAsEsm: [".ts"],
  roots: ["<rootDir>/test"],
  testMatch: ["**/*.test.ts"],
  moduleNameMapper: { "^(\\.{1,2}/.*)\\.js$": "$1" },
  watchman: false,
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      { useESM: true, diagnostics: { ignoreCodes: [151002] } },
    ],
  },
  collectCoverageFrom: ["src/**/*.ts", "!src/server.ts"],
};
