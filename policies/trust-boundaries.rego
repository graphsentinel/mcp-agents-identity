# MCPIdentity Trust Boundary Policy
package mcp.trust

default allow = false

# Operation permissions by trust level
operation_permissions = {
    "trusted": ["read", "write", "execute", "admin"],
    "semi-trusted": ["read", "list"],
    "untrusted": ["read"]
}

# Tool access by trust level
tool_permissions = {
    "trusted": ["filesystem", "database", "api", "shell", "network"],
    "semi-trusted": ["filesystem", "database", "api"],
    "untrusted": ["filesystem"]
}

# Main allow rule
allow {
    input.agent.svid_verified == true
    operation_allowed
    tool_allowed
}

# Operation permission check
operation_allowed {
    level := input.agent.trust_level
    allowed_ops := operation_permissions[level]
    input.operation == allowed_ops[_]
}

# Tool access check
tool_allowed {
    level := input.agent.trust_level
    allowed_tools := tool_permissions[level]
    input.tool == allowed_tools[_]
}

# Response
response = {
    "allowed": allow,
    "trust_level": input.agent.trust_level,
    "operation": input.operation,
    "tool": input.tool
}
