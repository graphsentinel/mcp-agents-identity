# MCPIdentity Tool Access Policy
# Fine-grained tool access control for MCP agents

package mcp.tools

import future.keywords.if
import future.keywords.in

default allow := false

# Tool definitions with required trust levels
tools := {
    "filesystem": {
        "read": {"min_trust": "untrusted", "requires_sandbox": false},
        "write": {"min_trust": "trusted", "requires_sandbox": false},
        "delete": {"min_trust": "trusted", "requires_sandbox": false}
    },
    "database": {
        "query": {"min_trust": "semi-trusted", "requires_sandbox": false},
        "insert": {"min_trust": "trusted", "requires_sandbox": false},
        "update": {"min_trust": "trusted", "requires_sandbox": false},
        "delete": {"min_trust": "trusted", "requires_sandbox": false}
    },
    "api": {
        "get": {"min_trust": "semi-trusted", "requires_sandbox": false},
        "post": {"min_trust": "trusted", "requires_sandbox": false},
        "put": {"min_trust": "trusted", "requires_sandbox": false},
        "delete": {"min_trust": "trusted", "requires_sandbox": false}
    },
    "shell": {
        "execute": {"min_trust": "trusted", "requires_sandbox": true}
    },
    "network": {
        "connect": {"min_trust": "trusted", "requires_sandbox": false},
        "listen": {"min_trust": "trusted", "requires_sandbox": true}
    }
}

# Trust level numeric values
trust_value := {
    "trusted": 3,
    "semi-trusted": 2,
    "untrusted": 1
}

# Check if agent has sufficient trust level
has_sufficient_trust(agent_level, required_level) if {
    trust_value[agent_level] >= trust_value[required_level]
}

# Main allow rule
allow if {
    # SVID must be verified
    input.agent.svid_verified == true

    # Tool and action must exist
    tool_config := tools[input.tool][input.action]

    # Check trust level
    has_sufficient_trust(input.agent.trust_level, tool_config.min_trust)

    # Check sandbox requirement
    sandbox_satisfied(tool_config)
}

# Sandbox requirement check
sandbox_satisfied(config) if {
    config.requires_sandbox == false
}

sandbox_satisfied(config) if {
    config.requires_sandbox == true
    input.sandbox_enabled == true
}

# Audit log entry
audit_entry := {
    "timestamp": time.now_ns(),
    "agent_id": input.agent.spiffe_id,
    "trust_level": input.agent.trust_level,
    "tool": input.tool,
    "action": input.action,
    "allowed": allow,
    "sandbox_enabled": object.get(input, "sandbox_enabled", false)
}

# List available tools for agent
available_tools[tool_name] if {
    some tool_name, actions in tools
    some action_name, config in actions
    has_sufficient_trust(input.agent.trust_level, config.min_trust)
}

# List available actions for a specific tool
available_actions[action_name] if {
    some action_name, config in tools[input.tool]
    has_sufficient_trust(input.agent.trust_level, config.min_trust)
}
