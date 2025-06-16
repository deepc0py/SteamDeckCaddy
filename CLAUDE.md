# Claude Code Project Memory

## Available Tools and Capabilities

### MCP Tools Available
- **`context7`** - Context management tool
- **`sequential-thinking`** - Sequential thinking assistance
- **`github`** - GitHub integration tool

### Development Workflow

#### Branch Strategy
- Create new branches for each task/ticket
- Branch naming should follow: `feature/`, `fix/`, `docs/`, etc.
- Each substantial task should have its own branch

#### Issue Management
- Create GitHub issues for planning and substantial tasks
- **Do NOT** create issues for small fixes or minor changes
- Issues should be used for:
  - Feature development planning
  - Bug tracking that requires investigation
  - Documentation improvements
  - Multi-step tasks or migrations

#### Pull Request Workflow
- **Always commit changes and create PRs** for tasks
- PR descriptions should specify which issues are resolved
- **Merge PRs to trigger builds** - builds are triggered by merged PRs
- Include issue numbers in PR descriptions (e.g., "Resolves #123")

#### Development Environment
- **Docker containers available** for development and testing
- **No TTL console/SSH access** - work within the constraints of available tools
- Use Docker appropriately for containerized development when needed

## Project Preferences
- Always commit and create PRs for completed work
- Reference and close GitHub issues in PRs when appropriate
- Focus on creating meaningful commits with clear messages
- Trigger builds through the PR merge process

## Notes
- This project uses CI/CD workflows that are triggered by PR merges
- Build artifacts and releases are generated automatically through GitHub Actions
- Cross-platform support is important (macOS, Linux, Windows)