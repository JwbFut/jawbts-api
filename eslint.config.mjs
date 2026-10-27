import nextConfig from "eslint-config-next";

const eslintConfig = [
    {
        ignores: [
            ".next/**",
            "node_modules/**",
            "src/generated/**",
            "next-env.d.ts",
        ],
    },
    ...nextConfig,
    {
        rules: {
            quotes: ["error", "double"],
            indent: ["error", 4, {
                "SwitchCase": 1,
                "VariableDeclarator": 1,
                "outerIIFEBody": 1,
                "MemberExpression": 1,
                "FunctionDeclaration": { "parameters": 1, "body": 1 },
                "FunctionExpression": { "parameters": 1, "body": 1 },
                "CallExpression": { "arguments": 1 },
                "ArrayExpression": 1,
                "ObjectExpression": 1,
                "ImportDeclaration": 1,
                "flatTernaryExpressions": false,
                "ignoreComments": false,
            }],
            "comma-dangle": ["error", "always-multiline"],
        },
    },
];

export default eslintConfig;
