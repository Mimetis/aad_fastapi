from typing import Optional


class AuthError(Exception):
    code: str

    def __init__(
        self,
        code: Optional[str] = None,
        description: Optional[str] = None,
        status_code=401,
        exception: Optional[Exception] = None,
    ):
        if exception is not None and code is None:
            if hasattr(exception, "error"):
                code = exception.error
            elif hasattr(exception, "code"):
                code = exception.code

        self.code = code

        if exception is not None and description is None:
            if hasattr(exception, "message"):
                description = exception.message
            elif hasattr(exception, "description"):
                description = exception.description
            elif hasattr(exception, "args") and len(exception.args) >= 1:
                description = exception.args[0]

        self.description = description
        super().__init__(description)

        self.status_code = status_code
