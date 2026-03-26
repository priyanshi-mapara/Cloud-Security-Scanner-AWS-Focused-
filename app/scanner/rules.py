from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from app.models.schemas import Finding, ResourceDocument, Severity


class Rule(ABC):
    rule_id: str
    title: str
    severity: Severity
    resource_type: str
    compliance_tags: list[str]
    remediation: str

    @abstractmethod
    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        raise NotImplementedError

    def _finding(self, resource_id: str, description: str) -> Finding:
        return Finding(
            finding_id=f"{self.rule_id}:{resource_id}",
            severity=self.severity,
            title=self.title,
            description=description,
            affected_resource=resource_id,
            remediation=self.remediation,
            compliance_tags=self.compliance_tags,
            resource_type=self.resource_type,
        )


class S3PublicAccessRule(Rule):
    rule_id = "S3-001"
    title = "S3 bucket is publicly accessible"
    severity = Severity.high
    resource_type = "s3_bucket"
    compliance_tags = ["CIS AWS Foundations 2.1.1"]
    remediation = "Enable Block Public Access and tighten bucket policy ACLs."

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        d = resource.data
        if d.get("public_access", False):
            return [self._finding(resource.resource_id, "Bucket allows public access.")]
        return []


class S3EncryptionDisabledRule(Rule):
    rule_id = "S3-002"
    title = "S3 bucket encryption is disabled"
    severity = Severity.high
    resource_type = "s3_bucket"
    compliance_tags = ["CIS AWS Foundations 2.1.4"]
    remediation = "Enable SSE-S3 or SSE-KMS for bucket default encryption."

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        if not resource.data.get("encryption_enabled", False):
            return [
                self._finding(
                    resource.resource_id, "Bucket encryption is not configured."
                )
            ]
        return []


class S3VersioningDisabledRule(Rule):
    rule_id = "S3-003"
    title = "S3 bucket versioning is disabled"
    severity = Severity.medium
    resource_type = "s3_bucket"
    compliance_tags = ["CIS AWS Foundations 2.1.5"]
    remediation = "Enable bucket versioning to protect against accidental data loss."

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        if not resource.data.get("versioning_enabled", False):
            return [
                self._finding(resource.resource_id, "Bucket versioning is disabled.")
            ]
        return []


class S3AccessLoggingDisabledRule(Rule):
    rule_id = "S3-004"
    title = "S3 bucket access logging disabled"
    severity = Severity.low
    resource_type = "s3_bucket"
    compliance_tags = ["CIS AWS Foundations 2.1.6"]
    remediation = "Enable server access logging to improve auditability."

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        if not resource.data.get("access_logging_enabled", False):
            return [
                self._finding(
                    resource.resource_id, "Server access logging is disabled."
                )
            ]
        return []


class IAMWildcardAdminRule(Rule):
    rule_id = "IAM-001"
    title = "IAM policy allows wildcard admin privileges"
    severity = Severity.critical
    resource_type = "iam_policy"
    compliance_tags = ["CIS AWS Foundations 1.16"]
    remediation = (
        "Replace wildcard actions/resources with least-privilege scoped permissions."
    )

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        statements = resource.data.get("statements", [])
        for statement in statements:
            actions = statement.get("actions", [])
            resources = statement.get("resources", [])
            if (
                "*" in actions
                and "*" in resources
                and statement.get("effect") == "Allow"
            ):
                return [
                    self._finding(
                        resource.resource_id,
                        "Policy grants wildcard administrative access.",
                    )
                ]
        return []


class IAMUserOldAccessKeyRule(Rule):
    rule_id = "IAM-002"
    title = "IAM user has old access keys"
    severity = Severity.medium
    resource_type = "iam_user"
    compliance_tags = ["CIS AWS Foundations 1.14"]
    remediation = "Rotate access keys older than 90 days and use temporary credentials."

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        age_days = resource.data.get("access_key_age_days", 0)
        if age_days > 90:
            return [
                self._finding(
                    resource.resource_id, f"Access key age is {age_days} days."
                )
            ]
        return []


class IAMUserMfaDisabledRule(Rule):
    rule_id = "IAM-003"
    title = "MFA not enabled for IAM user"
    severity = Severity.high
    resource_type = "iam_user"
    compliance_tags = ["CIS AWS Foundations 1.2"]
    remediation = "Enable MFA for all IAM users with console access."

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        if not resource.data.get("mfa_enabled", False):
            return [
                self._finding(resource.resource_id, "User does not have MFA enabled.")
            ]
        return []


class IAMRoleUnusedRule(Rule):
    rule_id = "IAM-004"
    title = "IAM role has not been used recently"
    severity = Severity.low
    resource_type = "iam_role"
    compliance_tags = ["CIS AWS Foundations 1.4"]
    remediation = "Review and remove stale IAM roles that are no longer needed."

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        last_used = resource.data.get("last_used")
        if not last_used:
            return [self._finding(resource.resource_id, "Role has never been used.")]
        used_dt = datetime.fromisoformat(last_used).replace(tzinfo=UTC)
        if (datetime.now(UTC) - used_dt).days > 180:
            return [
                self._finding(
                    resource.resource_id, "Role has not been used for over 180 days."
                )
            ]
        return []


class SGOpenSSHRule(Rule):
    rule_id = "EC2-001"
    title = "Security group allows 0.0.0.0/0 on SSH"
    severity = Severity.high
    resource_type = "security_group"
    compliance_tags = ["CIS AWS Foundations 4.1"]
    remediation = "Restrict port 22 ingress to approved administrative IP ranges."

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        for rule in resource.data.get("ingress_rules", []):
            if rule.get("port") == 22 and "0.0.0.0/0" in rule.get("cidrs", []):
                return [
                    self._finding(resource.resource_id, "Port 22 open to the internet.")
                ]
        return []


class SGOpenRDPRule(Rule):
    rule_id = "EC2-002"
    title = "Security group allows 0.0.0.0/0 on RDP"
    severity = Severity.high
    resource_type = "security_group"
    compliance_tags = ["CIS AWS Foundations 4.2"]
    remediation = "Restrict port 3389 ingress to authorized jump hosts or VPN ranges."

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        for rule in resource.data.get("ingress_rules", []):
            if rule.get("port") == 3389 and "0.0.0.0/0" in rule.get("cidrs", []):
                return [
                    self._finding(
                        resource.resource_id, "Port 3389 open to the internet."
                    )
                ]
        return []


class SGAllPortsOpenRule(Rule):
    rule_id = "EC2-003"
    title = "Security group allows all ports from internet"
    severity = Severity.critical
    resource_type = "security_group"
    compliance_tags = ["CIS AWS Foundations 4.3"]
    remediation = "Avoid 0-65535 ingress from 0.0.0.0/0 and segment network access."

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        for rule in resource.data.get("ingress_rules", []):
            if rule.get("port_range") == "0-65535" and "0.0.0.0/0" in rule.get(
                "cidrs", []
            ):
                return [
                    self._finding(
                        resource.resource_id, "All TCP ports exposed publicly."
                    )
                ]
        return []


class CloudTrailDisabledRule(Rule):
    rule_id = "CT-001"
    title = "CloudTrail is disabled"
    severity = Severity.critical
    resource_type = "cloudtrail"
    compliance_tags = ["CIS AWS Foundations 3.1"]
    remediation = "Enable CloudTrail in all regions for account activity logging."

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        if not resource.data.get("enabled", False):
            return [self._finding(resource.resource_id, "CloudTrail is disabled.")]
        return []


class CloudTrailNotMultiRegionRule(Rule):
    rule_id = "CT-002"
    title = "CloudTrail is not multi-region"
    severity = Severity.high
    resource_type = "cloudtrail"
    compliance_tags = ["CIS AWS Foundations 3.2"]
    remediation = "Configure CloudTrail as a multi-region trail."

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        if resource.data.get("enabled", False) and not resource.data.get(
            "is_multi_region", False
        ):
            return [
                self._finding(resource.resource_id, "Trail does not cover all regions.")
            ]
        return []


class CloudTrailLogValidationRule(Rule):
    rule_id = "CT-003"
    title = "CloudTrail log file validation is disabled"
    severity = Severity.medium
    resource_type = "cloudtrail"
    compliance_tags = ["CIS AWS Foundations 3.3"]
    remediation = "Enable CloudTrail log file integrity validation."

    def evaluate(self, resource: ResourceDocument) -> list[Finding]:
        if resource.data.get("enabled", False) and not resource.data.get(
            "log_file_validation_enabled", False
        ):
            return [
                self._finding(
                    resource.resource_id, "CloudTrail log file validation disabled."
                )
            ]
        return []


def build_rules() -> dict[str, list[Rule]]:
    rules: list[Rule] = [
        S3PublicAccessRule(),
        S3EncryptionDisabledRule(),
        S3VersioningDisabledRule(),
        S3AccessLoggingDisabledRule(),
        IAMWildcardAdminRule(),
        IAMUserOldAccessKeyRule(),
        IAMUserMfaDisabledRule(),
        IAMRoleUnusedRule(),
        SGOpenSSHRule(),
        SGOpenRDPRule(),
        SGAllPortsOpenRule(),
        CloudTrailDisabledRule(),
        CloudTrailNotMultiRegionRule(),
        CloudTrailLogValidationRule(),
    ]
    grouped: dict[str, list[Rule]] = {}
    for rule in rules:
        grouped.setdefault(rule.resource_type, []).append(rule)
    return grouped
