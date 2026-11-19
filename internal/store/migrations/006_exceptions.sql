-- The cached matching rule of every valid Exception resource (Task 22), keyed by the resource's
-- namespace and name. The rule is a findings.ExceptionRule as JSON with canonical advisory ids, so
-- Recompute reads exceptions without the Kubernetes API.
CREATE TABLE exceptions (
  namespace TEXT NOT NULL,
  name      TEXT NOT NULL,
  rule      TEXT NOT NULL,
  PRIMARY KEY (namespace, name)
);
