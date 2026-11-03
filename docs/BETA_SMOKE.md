# Beta Docker smoke

Temporary CI trigger to validate the complete single-YAML installation and HTTP startup in a hosted Linux environment. Hardware testing on Kali ARM64 is still required.

Revalidating the reconstructed bootstrap header and live startup.

Regression round: Docker-created workdir previously collided with current symlink; workaround fixed.

Round: grant non-root Core write access to SQLite database and WAL files created by the privileged broker.

Diagnostic rerun to inspect SQLite main/WAL/SHM ownership and Core volume writeability.

Now pin Docker source to the current base/main SHA, not the stale PR branch SHA.
