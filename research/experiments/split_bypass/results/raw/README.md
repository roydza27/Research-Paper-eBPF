# Raw run records

Store one JSON file per invocation or one JSON list of run records per file. Include the complete tool response or a path/hash to a separately preserved raw response. Keep stdout/stderr for failures and timeouts.

Never overwrite a raw result. Use a unique run ID and record the source commit, object SHA-256, policy SHA-256, tool versions, configuration, and exact command. These files are evidence; do not edit them during analysis. No raw run records are present in this initial scaffold.