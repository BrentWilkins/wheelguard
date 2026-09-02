-- Preserve the policy audit trail as append-only data.
CREATE TRIGGER policy_audit_reject_update
BEFORE UPDATE ON policy_audit
BEGIN
    SELECT RAISE(ABORT, 'policy_audit is append-only');
END;

CREATE TRIGGER policy_audit_reject_delete
BEFORE DELETE ON policy_audit
BEGIN
    SELECT RAISE(ABORT, 'policy_audit is append-only');
END;
