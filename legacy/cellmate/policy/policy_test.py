import unittest
from cellmate.policy.sitemap import Sitemap
from cellmate.policy.policy import Policy, Action


class TestBrowserActionPolicy(unittest.TestCase):

    def setUp(self):
        # Mock sitemap
        self.sitemap = Sitemap()
        self.sitemap.parse_sitemap_json([
            {
                "method": "POST",
                "url": "https://gitlab.com/groups/{group_name}/-/settings/repository/deploy_token/create",
                "tags": [
                    "create",
                    "deploy_token",
                    "group"
                ]
            },
            {
                "method": "POST",
                "url": "https://gitlab.com/{group_name}/{project_name}/-/settings/repository/deploy_token/create",
                "tags": [
                    "create",
                    "deploy_token"
                ]
            },
            {
                "method": "POST",
                "url": "https://gitlab.com/groups/{group_name}/-/deploy_tokens/{token_id}/revoke",
                "tags": [
                    "revoke",
                    "deploy_token"
                ]
            },
            {
                "method": "GET",
                "url": "https://gitlab.com/{group_name}/deprecated-repo",
                "tags": [
                    "read",
                    "repository",
                    "deprecated"
                ]
            },     # TODO: Define rules for matching endpoints in sitemap.
            {
                "method": "GET",
                "url": "https://gitlab.com/{group_name}/{project_name}",
                "tags": [
                    "read",
                    "repository"
                ]
            },
            {
                "category": "gitlab_members",
                "semantic_action": "Remove a member from a group or project",
                "url": "https://gitlab.com/{group}/{project}/-/project_members/{user_id}",
                "method": "POST",
                "body": {
                    "_method": "delete"
                },
                "tags": [
                    "project",
                    "member",
                    "delete"
                ]
            },
            {
                "category": "gitlab_issue_notes",
                "semantic_action": "Delete an issue note",
                "url": "https://gitlab.com/api/graphql",
                "method": "POST",
                "body": {
                    "operationName": "deleteWorkItemNote",
                    "variables": {
                        "input": {
                            "workItemTypeId": "gid://gitlab/WorkItems::Type/1"
                        }
                    }
                },
                "tags": [
                    "project",
                    "issue",
                    "note",
                    "delete"
                ]
            }
        ])

        self.policy_default_allow = Policy.from_dict({
            "name": "gitlab_policy_default_allow",
            "description": "Restricts sensitive GitLab actions involving deploy tokens.",
            "default": "allow",
            "domains": [
                "gitlab.com"
            ],
            "rules": [
                {
                    "effect": "deny",
                    "description": "Disallow creation of deploy tokens via group settings.",
                    "match": {
                        "tags": [
                            "create",
                            "deploy_token"
                        ]
                    }
                },
                {
                    "effect": "deny",
                    "description": "Disallow revocation of existing deploy tokens.",
                    "match": {
                        "endpoints": [
                            {
                                "method": "POST",
                                "url": "https://gitlab.com/groups/*/-/deploy_tokens/*/revoke"
                            }
                        ]
                    }
                },
                {
                    "effect": "deny",
                    "description": "Disallow delete project members.",
                    "match": {
                        "tags": [
                            "delete",
                            "member",
                            "project"
                        ]
                    }
                },
                {
                    "effect": "deny",
                    "description": "Disallow deleting issue notes.",
                    "match": {
                        "tags": [
                            "delete",
                            "issue",
                            "note"
                        ]
                    }
                }
            ]
        })

        self.policy_default_deny = Policy.from_dict({
            "name": "gitlab_policy_default_deny",
            "description": "Complex GitLab policy with exceptions.",
            "default": "deny",
            "domains": '*',
            "rules": [
                {
                    "effect": "allow",
                    "match": {
                        "tags": [
                            "repository",
                            "read",
                        ]
                    },
                    "exceptions": [
                        {
                            "match": {
                                "fields": {"repo_name": "hello-world"},
                            }
                        },
                        {
                            "match": {
                                "tags": ["deprecated"]
                            }
                        },
                    ],
                    "description": "Allow read access to repositories except for deprecated ones or specific repos."
                },
                {
                    "effect": "allow",
                    "match": {
                        "tags": ["project", "member"],
                    },
                    "description": "Allow access to project members."
                }
            ]
        })

        self.policy_allow_all = Policy.from_dict({
            "name": "allow_all_actions",
            "description": "Allow all actions by default.",
            "default": "allow",
            "domains": '*',
            "rules": []
        })


        self.policy_match_all = Policy.from_dict({
            "name": "allow_public_all_actions",
            "description": "Allow all public actions by default.",
            "default": "deny",
            "domains": [
                "gitlab.com"
            ],
            "rules": [
                {
                    "effect": "allow_public",
                    "match": '*',
                    "description": "Allow public actions."
                }
            ]
        })

    
    def test_sitemap_get_tags(self):
        """Test that sitemap correctly retrieves tags for a given method and URL."""
        tags = self.sitemap.get_tags("POST", "https://gitlab.com/groups/mygroup/-/settings/repository/deploy_token/create")
        self.assertEqual(sorted(tags), ["create", "deploy_token", "group"])

        tags = self.sitemap.get_tags("GET", "https://gitlab.com/mygroup/myproject")
        self.assertEqual(sorted(tags), ["read", "repository"])

        tags = self.sitemap.get_tags("POST", "https://gitlab.com/groups/mygroup/-/deploy_tokens/123/revoke")
        self.assertEqual(sorted(tags), ["deploy_token", "revoke"])

        tags = self.sitemap.get_tags("POST", "https://gitlab.com/mygroup/myproject/-/project_members/123", {"_method": "delete"})
        self.assertEqual(sorted(tags), ["delete", "member", "project"])

    def test_allow_default(self):
        """Allow action if domain is in allowed domains when default is allow and
        action does not match any deny rules."""
        # Not tags found, should still allow
        action = Action.from_endpoint(
            url="https://collector.prd-278964.gl-product-analytics.com/com.snowplowanalytics.snowplow/tp2",
            method="POST",
            sitemap=self.sitemap,
        )
        self.assertEqual(self.policy_default_allow.evaluate(action), "deny")

        # Tags found, but no matching deny rules
        action = Action.from_endpoint(
            url="https://gitlab.com/mygroup/myproject",
            method="GET",
            sitemap=self.sitemap,
        )
        self.assertEqual(self.policy_default_allow.evaluate(action), "allow")


    def test_deny_domain_not_allowed(self):
        """Deny action if domain is not in allowed domains when default is allow."""
        action = Action.from_endpoint(
            url="https://attacker.com",
            method="GET",
            sitemap=self.sitemap,
        )
        self.assertEqual(self.policy_default_allow.evaluate(action), "deny")
    
    def test_allow_match_all_domains(self):
        """Allow action if domain matches all domains rule."""
        action = Action.from_endpoint(
            url="https://gitlab.com/mygroup/myproject",
            method="GET",
            sitemap=self.sitemap,
        )
        self.assertEqual(self.policy_default_allow.evaluate(action), "allow")
        self.assertEqual(self.policy_allow_all.evaluate(action), "allow")

    def test_match_all(self):
        """Test that match_all rule allows all actions."""
        action = Action.from_endpoint(
            url="https://gitlab.com/mygroup/myproject",
            method="GET",
            sitemap=self.sitemap,
        )
        self.assertEqual(self.policy_match_all.evaluate(action), "allow_public")

        action = Action.from_endpoint(
            url="https://gitlab.com/mygroup/myproject/-/settings/repository/deploy_token/create",
            method="POST",
            sitemap=self.sitemap,
        )
        self.assertEqual(self.policy_match_all.evaluate(action), "allow_public")

        # Policy not applicable -> deny
        action = Action.from_endpoint(
            url="https://github.com",
            method="POST",
            sitemap=self.sitemap,
        )
        self.assertEqual(self.policy_match_all.evaluate(action), "deny")

    def test_deny_match_deny_rule_tags(self):
        """Deny action if it matches a deny rule."""
        # Project deploy token creation, action tags == rule tags
        action = Action.from_endpoint(
            url="https://gitlab.com/mygroup/myproject/-/settings/repository/deploy_token/create",
            method="POST",
            sitemap=self.sitemap,
        )
        self.assertEqual(self.policy_default_allow.evaluate(action), "deny")

        # Group deploy token creation, action tags is a superset of rule tags
        action = Action.from_endpoint(
            url="https://gitlab.com/groups/mygroup/-/settings/repository/deploy_token/create",
            method="POST",
            sitemap=self.sitemap,
        )
        self.assertEqual(self.policy_default_allow.evaluate(action), "deny")
    
    def test_deny_match_deny_rule_endpoints(self):
        """Deny action if it matches a deny rule by endpoint."""
        # Group deploy token revocation
        action = Action.from_endpoint(
            url="https://gitlab.com/groups/mygroup/-/deploy_tokens/123/revoke",
            method="POST",
            sitemap=self.sitemap,
        )
        self.assertEqual(self.policy_default_allow.evaluate(action), "deny")
    
    def test_default_deny(self):
        """Deny action if default is deny and action does not match any allow rules."""
        action = Action.from_endpoint(
            url="https://attacker.com",
            method="GET",
            sitemap=self.sitemap,
        )
        self.assertEqual(self.policy_default_allow.evaluate(action), "deny")

    def test_allow_if_matched_allow_rule(self):
        """Test that default deny policy allows read access to repositories with exceptions."""
        # Read access to a specific repo
        action = Action.from_endpoint(
            url="https://gitlab.com/mygroup/myproject",
            method="GET",
            sitemap=self.sitemap,
        )
        self.assertEqual(self.policy_default_deny.evaluate(action), "allow")

    def test_deny_if_matched_exception_fields(self):
        """Test that default deny policy denies read access to a specific repo with exceptions."""
        # Read access to a deprecated repo
        action = Action.from_endpoint(
            url="https://gitlab.com/mygroup/hello-world",
            method="GET",
            sitemap=self.sitemap,
            body={"repo_name": "hello-world"}
        )
        self.assertEqual(self.policy_default_deny.evaluate(action), "deny")

    def test_deny_if_matched_exception_tags(self):
        """Test that default deny policy denies read access to a deprecated repo."""
        # Read access to a deprecated repo
        action = Action.from_endpoint(
            url="https://gitlab.com/mygroup/deprecated-repo",
            method="GET",
            sitemap=self.sitemap,
        )
        self.assertEqual(self.policy_default_deny.evaluate(action), "deny")


    def test_matched_request_body(self):
        """Test that action with matching request data is allowed."""
        tags = self.sitemap.get_tags("POST", "https://gitlab.com/mygroup/myproject/-/project_members/123", {"_method": "delete"})
        self.assertEqual(sorted(tags), ["delete", "member", "project"])
        action = Action.from_endpoint(
            url="https://gitlab.com/mygroup/myproject/-/project_members/123",
            method="POST",
            sitemap=self.sitemap,
            body={"_method": "delete"}
        )
        self.assertEqual(self.policy_default_allow.evaluate(action), "deny")

        self.assertEqual(self.policy_default_deny.evaluate(action), "allow")

        action_no_body = Action.from_endpoint(
            url="https://gitlab.com/mygroup/myproject/-/project_members/123",
            method="POST",
            sitemap=self.sitemap,
        )
        tags = self.sitemap.get_tags("POST", "https://gitlab.com/mygroup/myproject/-/project_members/123")
        self.assertEqual(sorted(tags), [])
        self.assertEqual(self.policy_default_deny.evaluate(action_no_body), "deny")
        self.assertEqual(self.policy_default_allow.evaluate(action_no_body), "allow")

    def test_matched_nested_request_body(self):
        """Test that action with nested request data is allowed."""
        tags = self.sitemap.get_tags("POST", "https://gitlab.com/api/graphql", {
            "operationName": "deleteWorkItemNote",
            "variables": {
                "input": {
                    "workItemTypeId": "gid://gitlab/WorkItems::Type/1"
                }
            }
        })
        self.assertEqual(sorted(tags), ["delete", "issue", "note", "project"])

        tags = self.sitemap.get_tags("POST", "https://gitlab.com/api/graphql", {
            "operationName": "deleteWorkItemNote",
        })
        self.assertEqual(sorted(tags), [])

        tags = self.sitemap.get_tags("POST", "https://gitlab.com/api/graphql", {
            "operationName": "deleteWorkItemNote",
            "variables": {
                "input": {
                    "workItemTypeId": "gid://gitlab/WorkItems::Type/2"
                }
            }
        })
        self.assertEqual(sorted(tags), [])

        action = Action.from_endpoint(
            url="https://gitlab.com/api/graphql",
            method="POST",
            sitemap=self.sitemap,
            body={
                "operationName": "deleteWorkItemNote",
                "variables": {
                    "input": {
                        "workItemTypeId": "gid://gitlab/WorkItems::Type/1"
                    },
                    "title": "Delete note"
                },
                "query": "query deleteWorkItemNote($input: DeleteWorkItemNoteInput!) { deleteWorkItemNote(input: $input) { errors } }"
            }
        )
        self.assertEqual(self.policy_default_allow.evaluate(action), "deny")
        self.assertEqual(self.policy_default_deny.evaluate(action), "deny")

    def test_most_restrictive_rule_wins(self):
        """Test that the most restrictive rule wins."""
        policy_match_multiple_rules_default_deny = Policy.from_dict({
            "name": "gitlab_policy_match_multiple_rules",
            "description": "Policy that matches multiple rules.",
            "default": "deny",
            "domains": [
                "gitlab.com"
            ],
            "rules": [
                {
                    "effect": "allow",
                    "match": {
                        "tags": ["create", "deploy_token", "group"]
                    },
                    "description": "Allow group to create deploy tokens."
                },
                {
                    "effect": "allow_public",
                    "match": {
                        "tags": ["create", "deploy_token"]
                    },
                    "description": "Allow public access to revoke deploy tokens."
                }
            ]
        })
        action = Action.from_endpoint(
            url="https://gitlab.com/groups/mygroup/-/settings/repository/deploy_token/create",
            method="POST",
            sitemap=self.sitemap,
        )
        tags = self.sitemap.get_tags("POST", "https://gitlab.com/groups/mygroup/-/settings/repository/deploy_token/create")
        self.assertEqual(sorted(tags), ["create", "deploy_token", "group"])
        self.assertEqual(policy_match_multiple_rules_default_deny.evaluate(action), "allow_public")

        policy_match_multiple_rules_default_allow = Policy.from_dict({
            "name": "gitlab_policy_match_multiple_rules",
            "description": "Policy that matches multiple rules.",
            "default": "allow",
            "domains": [
                "gitlab.com"
            ],
            "rules": [
                {
                    "effect": "allow_public",
                    "match": {
                        "tags": ["create", "deploy_token", "group"]
                    },
                    "description": "Allow group to create deploy tokens."
                },
                {
                    "effect": "deny",
                    "match": {
                        "tags": ["create", "deploy_token"]
                    },
                    "description": "Deny public access to revoke deploy tokens."
                }
            ]
        })

        self.assertEqual(policy_match_multiple_rules_default_allow.evaluate(action), "deny")

if __name__ == '__main__':
    unittest.main()
