# Analyst workspace to-do

Status: planned; not implemented.

Security requirements for this workspace are tracked in the
[security to-do](../SECURITY_ROADMAP.md), including identity, endpoint controls,
isolated execution, sharing permissions, and protection of provider credentials.

Build an extensible workspace in `notebooks/` where threat analysts and other
APT_Watch users can create their own features for the tool with AI assistance.

- [ ] Add JupyterHub for multi-user access and individual workspaces.
- [ ] Add JupyterLab as the environment for notebooks and feature development.
- [ ] Add Jupyter AI for help writing, explaining, debugging, and extending code.
- [ ] Enable users to create their own agents for gathering data, producing
  reports, and other analyst workflows, and integrate their work with APT_Watch.
- [ ] Let users optionally share notebooks, agents, reports, and custom features,
  and collaborate on that work with other users.
- [ ] Make AI connectivity provider-agnostic: users choose the service they trust
  and connect their own account or credentials. Include OpenAI, Anthropic,
  GitHub Copilot, and other providers as integration targets; determine each
  service's supported connection method during implementation.

Intended outcome: an analyst can choose an AI service, use its assistant to
build and run a custom data-gathering or reporting agent, and choose whether
to keep the work personal or share and develop it with collaborators.
