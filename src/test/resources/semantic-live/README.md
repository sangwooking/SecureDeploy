# Optional live Semantic Review fixture

This parse-only Spring source fixture contains no credentials, private records, external URLs or executable build scripts. It is not deployed or executed. Account data is only a type declaration; the repository implementation and surrounding authentication infrastructure are deliberately outside this small fixture's scope.

The account lookup and download endpoint allow a model to assess whether ownership/path verification needs additional review. No prompt tells the model to find a vulnerability. Zero candidates is an acceptable result and is not proof of safety.

A live test requires explicit authorization and an existing configured API key. Upload this fixture once in AI_ENHANCED mode only after a STANDARD preflight confirms no billable remediation findings. Keep the normal slice/request/output limits. Never retry paid requests automatically, log source/prompt/raw response bodies, or commit test login credentials.
