# Policies

The corpus generator requires an existing policy path and copies it here using a content-addressed filename. The manifest records both the original path/hash and the copied policy hash. This avoids silently editing the policy in place.

No policy is assigned an expected verdict. The same frozen policy should be used for baseline and experimental pipelines. Preserve a policy change as a new hash and a new experiment condition.
