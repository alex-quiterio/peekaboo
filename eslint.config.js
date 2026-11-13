// Enforces the layering: apps -> infrastructure -> application -> domain. Dependencies point inward only.
import tseslint from "typescript-eslint";

const noParentImports = {
  group: ["../*"],
  message: "Cross-folder imports use the layer aliases (@domain, @application, @infrastructure, @apps).",
};
const noIo = {
  group: ["node:*", "bun", "bun:*", "systeminformation", "@runonflux/*"],
  message: "No I/O here. Declare an interface in @domain/ports and implement it in @infrastructure.",
};
const layer = (name, why) => ({ group: [`@${name}`, `@${name}/*`], message: why });

const restrict = (files, patterns) => ({
  files,
  rules: { "no-restricted-imports": ["error", { patterns: [noParentImports, ...patterns] }] },
});

export default tseslint.config(
  { ignores: ["node_modules/"] },
  ...tseslint.configs.recommended,
  restrict(["src/domain/**/*.ts"], [
    noIo,
    layer("application", "The domain depends on nothing outside itself."),
    layer("infrastructure", "The domain depends on nothing outside itself."),
    layer("apps", "The domain depends on nothing outside itself."),
  ]),
  restrict(["src/application/**/*.ts"], [
    noIo,
    layer("infrastructure", "Use cases depend on domain interfaces, not on adapters."),
    layer("apps", "Use cases do not know about the apps that call them."),
  ]),
  restrict(["src/infrastructure/**/*.ts"], [layer("apps", "Infrastructure does not know about the apps.")]),
  restrict(["src/apps/cli/**/*.ts"], [{ group: ["@apps/web", "@apps/web/*"], message: "Apps do not import each other." }]),
  restrict(["src/apps/web/**/*.ts"], [{ group: ["@apps/cli", "@apps/cli/*"], message: "Apps do not import each other." }]),
  // Tests may use the test runner in any layer.
  {
    files: ["src/**/*.test.ts"],
    rules: { "no-restricted-imports": ["error", { patterns: [noParentImports] }] },
  },
);
