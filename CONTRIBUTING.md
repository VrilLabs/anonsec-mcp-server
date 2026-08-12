# Contributing to Firefox Relay MCP Server

Contributions are welcome! Please follow these guidelines when contributing to this project.

## Code Style

- **TypeScript**: Use strict mode
- **Naming**: Use camelCase for variables and functions, PascalCase for types and classes
- **Imports**: Group imports by source (external, then internal)
- **Comments**: Use JSDoc for exported functions and classes
- **Line Length**: Keep lines under 120 characters when possible

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
feat: add new tool for email filtering
fix: correct OTP extraction regex pattern
chore: update dependencies
refactor: improve error handling in tools
docs: update README with usage examples
```

### Commit Types

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Changes that do not affect the meaning of the code (white-space, formatting, missing semi-colons, etc)
- `refactor`: A code change that neither fixes a bug nor adds a feature
- `perf`: A code change that improves performance
- `test`: Adding missing tests
- `chore`: Changes to the build process or auxiliary tools and libraries such as documentation generation

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'feat: add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/anonsec-mcp-server.git
cd anonsec-mcp-server

# Install dependencies
npm install

# Run the development server
npm run dev
```

## Running Tests

```bash
# Run all tests
npm test

# Run with coverage
npm run test:coverage

# Run linter
npm run lint

# Type checking
npm run typecheck
```

## Reporting Issues

Before creating an issue, please:

1. Check the [existing issues](https://github.com/your-org/anonsec-mcp-server/issues) to see if it has already been reported
2. Provide a clear and descriptive title
3. Include steps to reproduce the issue
4. Include your Node.js version (`node --version`)
5. Include your npm version (`npm --version`)

## Code Review Process

- All pull requests require at least one approval from a maintainer
- CI checks must pass before merging
- Code must follow the established style guidelines
- All tests must pass

## Security

If you discover a security vulnerability, please see [SECURITY.md](SECURITY.md) for the vulnerability reporting process.
